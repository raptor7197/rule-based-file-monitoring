"""AI-Driven File Integrity Monitoring using rule-based reasoning.

This script provides a polling-based file integrity monitor that follows the
algorithm outlined by the user:

1. Establishes a baseline for every file within a directory.
2. Continuously monitors the directory at a configurable interval.
3. Collects metadata and evaluates rule-based conditions for each event.
4. Emits alerts whenever the cumulative risk score meets a threshold.

Configuration is done via the ``CONFIG`` object near the bottom of the file so
the monitor can be launched directly as a script without command-line flags.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import pwd
import threading
import time
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Optional

LOGGER = logging.getLogger("ai_fim")


@dataclasses.dataclass
class FileMetadata:
    """Metadata snapshot for a file stored in the baseline or collected events."""

    path: str
    size: int
    mtime: float
    atime: float
    owner: str
    sha256: str

    @classmethod
    def from_path(cls, path: Path) -> "FileMetadata":
        stat = path.stat()
        owner_name = pwd.getpwuid(stat.st_uid).pw_name
        return cls(
            path=str(path),
            size=stat.st_size,
            mtime=stat.st_mtime,
            atime=stat.st_atime,
            owner=owner_name,
            sha256=hash_file(path),
        )


@dataclasses.dataclass
class FileEvent:
    """Detected file activity event."""

    event_type: str
    timestamp: float
    metadata_current: Optional[FileMetadata]
    metadata_baseline: Optional[FileMetadata]


@dataclasses.dataclass
class RuleHit:
    """Represents a triggered rule."""

    name: str
    detail: str


@dataclasses.dataclass
class RunSummary:
    """Aggregated information for a monitoring iteration."""

    timestamp: float
    events_by_type: Dict[str, int]
    normal_counts_by_type: Dict[str, int]
    anomaly_counts_by_type: Dict[str, int]
    rule_hits: Dict[str, int]


@dataclasses.dataclass
class MonitorConfig:
    """Configuration container for the monitoring script."""

    directory: str = "./watched_dir"
    baseline: str = "baseline.json"
    alert_log: str = "alerts.log"
    report_dir: str = "reports"
    interval: int = 30
    working_hours: str = "08:00-18:00"
    authorized_users: List[str] = dataclasses.field(default_factory=list)
    frequency_threshold: int = 5
    frequency_window: int = 300
    size_change_limit: int = 1024 * 1024
    risk_threshold: int = 2
    initialize_baseline: bool = False
    approve: List[str] = dataclasses.field(default_factory=list)
    run_once: bool = False
    verbose_logging: bool = False
    enable_reports: bool = True


def hash_file(path: Path, chunk_size: int = 64 * 1024) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class BaselineStore:
    """Persists metadata snapshots to a JSON file."""

    def __init__(self, store_path: Path) -> None:
        self.store_path = store_path
        self._baseline: Dict[str, FileMetadata] = {}
        if store_path.exists():
            self.load()

    def load(self) -> None:
        data = json.loads(self.store_path.read_text())
        self._baseline = {
            path: FileMetadata(**metadata) for path, metadata in data.items()
        }
        LOGGER.info("Baseline loaded from %s", self.store_path)

    def save(self) -> None:
        serializable = {path: dataclasses.asdict(meta) for path, meta in self._baseline.items()}
        self.store_path.write_text(json.dumps(serializable, indent=2))
        LOGGER.info("Baseline persisted to %s", self.store_path)

    def get(self, path: str) -> Optional[FileMetadata]:
        return self._baseline.get(path)

    def update(self, metadata: FileMetadata) -> None:
        self._baseline[metadata.path] = metadata

    def remove(self, path: str) -> None:
        self._baseline.pop(path, None)

    def items(self) -> Iterable[tuple[str, FileMetadata]]:
        return self._baseline.items()


class RuleEngine:
    """Evaluates rule base R for each file event."""

    def __init__(
        self,
        authorized_users: Optional[List[str]],
        working_hours: tuple[dt.time, dt.time],
        frequency_threshold: int,
        frequency_window_seconds: int,
        size_change_limit_bytes: int,
    ) -> None:
        self.authorized_users = authorized_users or []
        self.working_hours = working_hours
        self.frequency_threshold = frequency_threshold
        self.frequency_window_seconds = frequency_window_seconds
        self.size_change_limit_bytes = size_change_limit_bytes
        self._access_tracker: Dict[str, Deque[float]] = defaultdict(deque)

    def _register_event(self, event: FileEvent) -> int:
        deque_for_file = self._access_tracker[event.metadata_baseline.path if event.metadata_baseline else event.metadata_current.path]  # type: ignore[arg-type]
        now = event.timestamp
        deque_for_file.append(now)
        cutoff = now - self.frequency_window_seconds
        while deque_for_file and deque_for_file[0] < cutoff:
            deque_for_file.popleft()
        return len(deque_for_file)

    def evaluate(self, event: FileEvent) -> List[RuleHit]:
        hits: List[RuleHit] = []
        baseline = event.metadata_baseline
        current = event.metadata_current

        if current and baseline and current.sha256 != baseline.sha256:
            hits.append(RuleHit("Hash Mismatch", "Current hash differs from baseline"))

        user = (current or baseline).owner if (current or baseline) else None
        if user and self.authorized_users and user not in self.authorized_users:
            hits.append(RuleHit("Unauthorized User", f"Owner {user} not authorized"))

        start, end = self.working_hours
        timestamp = dt.datetime.fromtimestamp(event.timestamp).time()
        if not (start <= timestamp <= end):
            hits.append(RuleHit("Suspicious Timing", f"Event outside {start}-{end}"))

        events_in_window = self._register_event(event)
        if events_in_window > self.frequency_threshold:
            hits.append(
                RuleHit(
                    "Abnormal Frequency",
                    f"{events_in_window} events within {self.frequency_window_seconds}s",
                )
            )

        if current and baseline:
            size_delta = abs(current.size - baseline.size)
            if size_delta > self.size_change_limit_bytes:
                hits.append(
                    RuleHit(
                        "Size Deviation",
                        f"Size changed by {size_delta} bytes",
                    )
                )

        return hits


class DecisionEngine:
    def __init__(self, risk_threshold: int) -> None:
        self.risk_threshold = risk_threshold

    def classify(self, hits: List[RuleHit]) -> str:
        return "Anomaly" if len(hits) >= self.risk_threshold else "Normal"


class AlertDispatcher:
    def __init__(self, alert_log: Path) -> None:
        self.alert_log = alert_log

    def dispatch(self, event: FileEvent, hits: List[RuleHit]) -> None:
        alert_record = {
            "timestamp": dt.datetime.fromtimestamp(event.timestamp).isoformat(),
            "path": (event.metadata_current or event.metadata_baseline).path,
            "event_type": event.event_type,
            "triggered_rules": [hit.name for hit in hits],
            "details": [hit.detail for hit in hits],
        }
        with self.alert_log.open("a") as handle:
            handle.write(json.dumps(alert_record) + "\n")
        LOGGER.warning("ALERT: %s", json.dumps(alert_record))


class ReportGenerator:
    """Creates color-coded graphs for each monitoring iteration."""

    def __init__(self, report_dir: Path) -> None:
        self.report_dir = report_dir
        self.report_dir.mkdir(parents=True, exist_ok=True)
        try:
            import matplotlib

            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError as exc:  # pragma: no cover - depends on local env
            raise RuntimeError(
                "matplotlib is required for report generation. Install it via 'pip install matplotlib'."
            ) from exc

        self._plt = plt
        self._colors = {
            "Normal": "#2ca02c",
            "Anomaly": "#d62728",
        }

    def generate(self, summary: RunSummary) -> Path:
        plt = self._plt
        timestamp = dt.datetime.fromtimestamp(summary.timestamp)
        filename = f"fim_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.png"
        output_path = self.report_dir / filename

        event_types = sorted(summary.events_by_type.keys())

        fig, ax = plt.subplots(figsize=(8, 4.5))
        if event_types:
            normal_values = [summary.normal_counts_by_type.get(evt, 0) for evt in event_types]
            anomaly_values = [summary.anomaly_counts_by_type.get(evt, 0) for evt in event_types]

            ax.bar(
                event_types,
                normal_values,
                color=self._colors["Normal"],
                label="Normal",
            )
            ax.bar(
                event_types,
                anomaly_values,
                bottom=normal_values,
                color=self._colors["Anomaly"],
                label="Anomaly",
            )
            ax.set_ylabel("Events")
            ax.set_title(f"File Activity Classification – {timestamp.isoformat(timespec='seconds')}")
            ax.legend()
        else:
            ax.text(0.5, 0.5, "No Events Detected", ha="center", va="center", fontsize=14)
            ax.axis("off")

        # Secondary summary text.
        text_lines = [
            f"Total Events: {sum(summary.events_by_type.values())}",
            f"Rules Triggered: {sum(summary.rule_hits.values())}",
        ]
        if summary.rule_hits:
            top_rules = ", ".join(f"{name} ({count})" for name, count in summary.rule_hits.items())
            text_lines.append(f"Rule Breakdown: {top_rules}")
        fig.text(0.01, 0.01, "\n".join(text_lines), fontsize=9, ha="left", va="bottom")

        fig.tight_layout()
        fig.savefig(output_path, bbox_inches="tight")
        plt.close(fig)
        return output_path


class FileIntegrityMonitor:
    def __init__(
        self,
        directory: Path,
        baseline_store: BaselineStore,
        rule_engine: RuleEngine,
        decision_engine: DecisionEngine,
        alert_dispatcher: AlertDispatcher,
        interval_seconds: int,
        report_generator: Optional[ReportGenerator],
    ) -> None:
        self.directory = directory
        self.baseline_store = baseline_store
        self.rule_engine = rule_engine
        self.decision_engine = decision_engine
        self.alert_dispatcher = alert_dispatcher
        self.interval_seconds = interval_seconds
        self.report_generator = report_generator
        self._stop_event = threading.Event()

    def initialize(self) -> None:
        LOGGER.info("Initializing baseline for %s", self.directory)
        for file_path in self._iter_files():
            metadata = FileMetadata.from_path(file_path)
            self.baseline_store.update(metadata)
        self.baseline_store.save()

    def _iter_files(self) -> Iterable[Path]:
        for root, _dirs, files in os.walk(self.directory):
            for filename in files:
                yield Path(root) / filename

    def _detect_events(self) -> List[FileEvent]:
        now = time.time()
        events: List[FileEvent] = []
        seen_paths = set()

        for file_path in self._iter_files():
            seen_paths.add(str(file_path))
            baseline = self.baseline_store.get(str(file_path))
            current_meta = FileMetadata.from_path(file_path)
            if not baseline:
                events.append(
                    FileEvent(
                        event_type="Create",
                        timestamp=now,
                        metadata_current=current_meta,
                        metadata_baseline=None,
                    )
                )
                continue

            if current_meta.sha256 != baseline.sha256 or current_meta.size != baseline.size:
                events.append(
                    FileEvent(
                        event_type="Modify",
                        timestamp=now,
                        metadata_current=current_meta,
                        metadata_baseline=baseline,
                    )
                )
            elif current_meta.atime > baseline.atime:
                events.append(
                    FileEvent(
                        event_type="Access",
                        timestamp=now,
                        metadata_current=current_meta,
                        metadata_baseline=baseline,
                    )
                )

        for baseline_path, baseline_meta in self.baseline_store.items():
            if baseline_path not in seen_paths:
                events.append(
                    FileEvent(
                        event_type="Delete",
                        timestamp=now,
                        metadata_current=None,
                        metadata_baseline=baseline_meta,
                    )
                )
        return events

    def run_once(self) -> None:
        events = self._detect_events()
        iteration_timestamp = time.time()
        events_by_type: Counter[str] = Counter()
        normal_by_type: Counter[str] = Counter()
        anomaly_by_type: Counter[str] = Counter()
        rule_hits: Counter[str] = Counter()

        for event in events:
            hits = self.rule_engine.evaluate(event)
            classification = self.decision_engine.classify(hits)
            LOGGER.info(
                "%s %s classified as %s (%d rule hits)",
                event.event_type,
                (event.metadata_current or event.metadata_baseline).path,
                classification,
                len(hits),
            )
            if classification == "Anomaly":
                self.alert_dispatcher.dispatch(event, hits)

            events_by_type[event.event_type] += 1
            if classification == "Anomaly":
                anomaly_by_type[event.event_type] += 1
            else:
                normal_by_type[event.event_type] += 1
            for hit in hits:
                rule_hits[hit.name] += 1

        if self.report_generator:
            summary = RunSummary(
                timestamp=iteration_timestamp,
                events_by_type=dict(events_by_type),
                normal_counts_by_type=dict(normal_by_type),
                anomaly_counts_by_type=dict(anomaly_by_type),
                rule_hits=dict(rule_hits),
            )
            report_path = self.report_generator.generate(summary)
            LOGGER.info("Report saved to %s", report_path)

    def run_forever(self) -> None:
        LOGGER.info("Starting monitoring loop (interval=%ss)", self.interval_seconds)
        while not self._stop_event.is_set():
            self.run_once()
            self._stop_event.wait(self.interval_seconds)

    def stop(self) -> None:
        self._stop_event.set()

    def approve_change(self, path: Path) -> None:
        metadata = FileMetadata.from_path(path)
        self.baseline_store.update(metadata)
        self.baseline_store.save()
        LOGGER.info("Baseline updated for %s", path)


# --------------------------------------------------------------------------- #
# Configuration – adjust the values below to tune how the monitor runs.
# --------------------------------------------------------------------------- #
CONFIG = MonitorConfig(
    directory=os.environ.get("AI_FIM_DIRECTORY", "./watched_dir"),
    baseline=os.environ.get("AI_FIM_BASELINE", "baseline.json"),
    alert_log=os.environ.get("AI_FIM_ALERT_LOG", "alerts.log"),
    report_dir=os.environ.get("AI_FIM_REPORT_DIR", "reports"),
    interval=int(os.environ.get("AI_FIM_INTERVAL", "30")),
    working_hours=os.environ.get("AI_FIM_WORKING_HOURS", "08:00-18:00"),
    authorized_users=[
        user.strip()
        for user in os.environ.get("AI_FIM_AUTH_USERS", "").split(",")
        if user.strip()
    ],
    frequency_threshold=int(os.environ.get("AI_FIM_FREQ_THRESHOLD", "5")),
    frequency_window=int(os.environ.get("AI_FIM_FREQ_WINDOW", "300")),
    size_change_limit=int(os.environ.get("AI_FIM_SIZE_LIMIT", str(1024 * 1024))),
    risk_threshold=int(os.environ.get("AI_FIM_RISK_THRESHOLD", "2")),
    initialize_baseline=os.environ.get("AI_FIM_INIT_BASELINE", "true").lower()
    in {"1", "true", "yes"},
    approve=[
        path.strip()
        for path in os.environ.get("AI_FIM_APPROVE", "").split(",")
        if path.strip()
    ],
    run_once=os.environ.get("AI_FIM_RUN_ONCE", "false").lower() in {"1", "true", "yes"},
    verbose_logging=os.environ.get("AI_FIM_VERBOSE", "false").lower()
    in {"1", "true", "yes"},
    enable_reports=os.environ.get("AI_FIM_REPORTS", "true").lower()
    in {"1", "true", "yes"},
)


def parse_working_hours(value: str) -> tuple[dt.time, dt.time]:
    start_str, end_str = value.split("-", maxsplit=1)
    return dt.datetime.strptime(start_str, "%H:%M").time(), dt.datetime.strptime(end_str, "%H:%M").time()


def build_monitor(config: MonitorConfig) -> FileIntegrityMonitor:
    directory = Path(config.directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    baseline_store = BaselineStore(Path(config.baseline).resolve())
    rule_engine = RuleEngine(
        authorized_users=config.authorized_users,
        working_hours=parse_working_hours(config.working_hours),
        frequency_threshold=config.frequency_threshold,
        frequency_window_seconds=config.frequency_window,
        size_change_limit_bytes=config.size_change_limit,
    )
    decision_engine = DecisionEngine(risk_threshold=config.risk_threshold)
    alert_dispatcher = AlertDispatcher(Path(config.alert_log).resolve())
    report_generator: Optional[ReportGenerator] = None
    if config.enable_reports:
        report_generator = ReportGenerator(Path(config.report_dir).resolve())
    return FileIntegrityMonitor(
        directory=directory,
        baseline_store=baseline_store,
        rule_engine=rule_engine,
        decision_engine=decision_engine,
        alert_dispatcher=alert_dispatcher,
        interval_seconds=config.interval,
        report_generator=report_generator,
    )


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s")


def main() -> None:
    config = CONFIG
    configure_logging(config.verbose_logging)

    monitor = build_monitor(config)

    if config.initialize_baseline:
        monitor.initialize()

    if config.approve:
        for file_path in config.approve:
            monitor.approve_change(Path(file_path).resolve())

    if config.run_once:
        monitor.run_once()
    else:
        monitor.run_forever()


if __name__ == "__main__":
    main()
