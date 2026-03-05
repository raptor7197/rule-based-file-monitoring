from __future__ import annotations

import json
import os
from collections import Counter, deque
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd
import streamlit as st

from ai_rule_based_fim import CONFIG, MonitorConfig, build_monitor


def human_bytes(size: int) -> str:
    if size < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024.0:
            return f"{value:,.2f} {unit}"
        value /= 1024.0
    return f"{value:,.2f} PB"


def collect_directory_stats(directory: Path) -> Dict[str, int]:
    total_files = 0
    total_size = 0
    if not directory.exists():
        return {"files": 0, "size": 0}
    for root, _dirs, files in os.walk(directory):
        for filename in files:
            total_files += 1
            try:
                total_size += (Path(root) / filename).stat().st_size
            except FileNotFoundError:
                continue
    return {"files": total_files, "size": total_size}


def load_baseline_stats(baseline_path: Path) -> Dict[str, int]:
    if not baseline_path.exists():
        return {"files": 0, "size": 0}
    try:
        data = json.loads(baseline_path.read_text())
    except json.JSONDecodeError:
        return {"files": 0, "size": 0}
    total_size = 0
    for metadata in data.values():
        total_size += int(metadata.get("size", 0))
    return {"files": len(data), "size": total_size}


def load_alerts(alert_log: Path, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    if not alert_log.exists():
        return []
    if limit is None:
        records: List[Dict[str, Any]] = []
        with alert_log.open("r") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records

    records_deque: deque[Dict[str, Any]] = deque(maxlen=limit)
    with alert_log.open("r") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                records_deque.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(records_deque)


def list_reports(report_dir: Path) -> List[Path]:
    if not report_dir.exists():
        return []
    reports = [path for path in report_dir.glob("*.png") if path.is_file()]
    return sorted(reports, key=lambda path: path.stat().st_mtime, reverse=True)


def build_config_from_sidebar() -> MonitorConfig:
    with st.sidebar:
        st.header("Monitor Configuration")

        directory = st.text_input("Watched directory", value=CONFIG.directory)
        baseline = st.text_input("Baseline file", value=CONFIG.baseline)
        alert_log = st.text_input("Alert log", value=CONFIG.alert_log)
        report_dir = st.text_input("Report directory", value=CONFIG.report_dir)

        interval = st.number_input(
            "Polling interval (seconds)", min_value=5, value=CONFIG.interval
        )
        working_hours = st.text_input(
            "Working hours (HH:MM-HH:MM)", value=CONFIG.working_hours
        )

        authorized_users = st.text_input(
            "Authorized users (comma-separated)",
            value=",".join(CONFIG.authorized_users),
        )

        frequency_threshold = st.number_input(
            "Frequency threshold",
            min_value=1,
            value=CONFIG.frequency_threshold,
        )
        frequency_window = st.number_input(
            "Frequency window (seconds)",
            min_value=30,
            value=CONFIG.frequency_window,
        )

        size_change_limit = st.number_input(
            "Size change limit (bytes)",
            min_value=0,
            value=CONFIG.size_change_limit,
        )
        risk_threshold = st.number_input(
            "Risk threshold (rule hits)",
            min_value=1,
            value=CONFIG.risk_threshold,
        )

        enable_reports = st.checkbox("Enable reports", value=CONFIG.enable_reports)

    return MonitorConfig(
        directory=directory,
        baseline=baseline,
        alert_log=alert_log,
        report_dir=report_dir,
        interval=int(interval),
        working_hours=working_hours,
        authorized_users=[
            user.strip() for user in authorized_users.split(",") if user.strip()
        ],
        frequency_threshold=int(frequency_threshold),
        frequency_window=int(frequency_window),
        size_change_limit=int(size_change_limit),
        risk_threshold=int(risk_threshold),
        initialize_baseline=False,
        approve=[],
        run_once=True,
        verbose_logging=False,
        enable_reports=enable_reports,
    )


def main() -> None:
    st.set_page_config(page_title="AI Rule-Based FIM", layout="wide")
    st.title("AI Rule-Based File Integrity Monitoring Dashboard")
    st.write(
        "Use this dashboard to run a single monitoring iteration, review alerts, "
        "and inspect data volume metrics for the watched directory."
    )

    config = build_config_from_sidebar()
    try:
        monitor = build_monitor(config)
    except RuntimeError as exc:
        if "matplotlib" in str(exc):
            st.warning(
                "Reports are disabled because matplotlib is not available. "
                "Install it to enable report generation."
            )
            config.enable_reports = False
            monitor = build_monitor(config)
        else:
            raise

    action_col, approve_col, _ = st.columns([1, 2, 3])
    with action_col:
        if st.button("Run one iteration", type="primary"):
            with st.spinner("Running monitoring iteration..."):
                monitor.run_once()
            st.success("Monitoring iteration completed.")

    with approve_col:
        approve_path = st.text_input("Approve file path (updates baseline)")
        if st.button("Approve change"):
            if approve_path.strip():
                with st.spinner("Approving change..."):
                    monitor.approve_change(Path(approve_path).expanduser().resolve())
                st.success("Baseline updated for the approved file.")
            else:
                st.warning("Enter a valid file path to approve.")

    if st.button("Initialize baseline"):
        with st.spinner("Initializing baseline..."):
            monitor.initialize()
        st.success("Baseline initialized.")

    directory_path = Path(config.directory).expanduser().resolve()
    baseline_path = Path(config.baseline).expanduser().resolve()
    alert_log_path = Path(config.alert_log).expanduser().resolve()
    report_dir_path = Path(config.report_dir).expanduser().resolve()

    dir_stats = collect_directory_stats(directory_path)
    baseline_stats = load_baseline_stats(baseline_path)
    alerts = load_alerts(alert_log_path)

    total_alerts = len(alerts)
    size_delta = dir_stats["size"] - baseline_stats["size"]
    coverage = (
        (baseline_stats["files"] / dir_stats["files"]) * 100
        if dir_stats["files"] > 0
        else 0.0
    )

    st.subheader("Data Volume Overview")
    metric_cols = st.columns(5)
    metric_cols[0].metric("Watched Files", f"{dir_stats['files']:,}")
    metric_cols[1].metric("Watched Size", human_bytes(dir_stats["size"]))
    metric_cols[2].metric("Baseline Files", f"{baseline_stats['files']:,}")
    metric_cols[3].metric("Baseline Size", human_bytes(baseline_stats["size"]))
    metric_cols[4].metric("Size Delta", human_bytes(size_delta))

    st.caption(f"Baseline coverage: {coverage:.1f}% of watched files")

    st.subheader("Alerts Summary")
    if alerts:
        event_type_counts = Counter(
            alert.get("event_type", "Unknown") for alert in alerts
        )
        df_counts = pd.DataFrame.from_dict(
            event_type_counts, orient="index", columns=["Count"]
        )
        st.bar_chart(df_counts)

        recent_alerts = load_alerts(alert_log_path, limit=25)
        df_alerts = pd.DataFrame(recent_alerts)
        if not df_alerts.empty:
            st.dataframe(df_alerts, use_container_width=True)
        st.caption(f"Total alerts: {total_alerts:,}")
    else:
        st.info("No alerts recorded yet.")

    st.subheader("Latest Reports")
    if not config.enable_reports:
        st.info(
            "Reports are disabled. Enable reports and install matplotlib to view them."
        )
    else:
        reports = list_reports(report_dir_path)
        if reports:
            for report_path in reports[:3]:
                st.image(
                    str(report_path), caption=report_path.name, use_container_width=True
                )
        else:
            st.info(
                "No reports found. Enable reports and run an iteration to generate one."
            )


if __name__ == "__main__":
    main()
