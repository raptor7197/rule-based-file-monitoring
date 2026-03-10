from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st

from ai_rule_based_fim import CONFIG, MonitorConfig, build_monitor


def human_bytes(size: int) -> str:
    neg = size < 0
    value = float(abs(size))
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024.0:
            s = f"{value:,.2f} {unit}"
            return f"-{s}" if neg else s
        value /= 1024.0
    s = f"{value:,.2f} PB"
    return f"-{s}" if neg else s


def sha256_file(path: Path, chunk_size: int = 64 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_key(path_str: str) -> str:
    return hashlib.sha256(path_str.encode()).hexdigest()


def collect_directory_stats(directory: Path) -> Dict[str, int]:
    total_files = 0
    total_size = 0
    if not directory.exists():
        return {"files": 0, "size": 0}
    for root, _dirs, files in os.walk(directory):
        for filename in files:
            p = Path(root) / filename
            try:
                total_files += 1
                total_size += p.stat().st_size
            except FileNotFoundError:
                continue
    return {"files": total_files, "size": total_size}


def load_baseline_data(baseline_path: Path) -> Dict[str, Dict[str, Any]]:
    if not baseline_path.exists():
        return {}
    try:
        data = json.loads(baseline_path.read_text())
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def load_baseline_stats(baseline_path: Path) -> Dict[str, int]:
    data = load_baseline_data(baseline_path)
    total_size = sum(int(m.get("size", 0)) for m in data.values())
    return {"files": len(data), "size": total_size}


def load_alerts(alert_log: Path, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    if not alert_log.exists():
        return []
    if limit is None:
        out: List[Dict[str, Any]] = []
        with alert_log.open("r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out
    q: deque[Dict[str, Any]] = deque(maxlen=limit)
    with alert_log.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                q.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(q)


def list_reports(report_dir: Path) -> List[Path]:
    if not report_dir.exists():
        return []
    files = [p for p in report_dir.glob("*.png") if p.is_file()]
    return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)


def ensure_snapshots(
    baseline_data: Dict[str, Dict[str, Any]],
    snapshot_dir: Path,
) -> Dict[str, str]:
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    map_path = snapshot_dir / "snapshot_map.json"
    try:
        snapshot_map: Dict[str, str] = (
            json.loads(map_path.read_text()) if map_path.exists() else {}
        )
        if not isinstance(snapshot_map, dict):
            snapshot_map = {}
    except json.JSONDecodeError:
        snapshot_map = {}

    changed = False
    for path_str in baseline_data:
        src = Path(path_str)
        if path_str in snapshot_map and Path(snapshot_map[path_str]).exists():
            continue
        if src.exists() and src.is_file():
            key = safe_key(path_str)
            target = snapshot_dir / f"{key}.bin"
            try:
                shutil.copy2(src, target)
                snapshot_map[path_str] = str(target)
                changed = True
            except Exception:
                continue
    if changed:
        map_path.write_text(json.dumps(snapshot_map, indent=2))
    return snapshot_map


def content_deviation_percent(original: Path, current: Path) -> float:
    try:
        a = original.read_bytes()
        b = current.read_bytes()
    except Exception:
        return 0.0
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 0.0
    min_len = min(len(a), len(b))
    diff = sum(1 for i in range(min_len) if a[i] != b[i])
    diff += max_len - min_len
    return (diff / max_len) * 100.0


# ---------------------------------------------------------------------------
# Integrity analysis + modification error log
# ---------------------------------------------------------------------------


def analyze_integrity(
    baseline_data: Dict[str, Dict[str, Any]],
    snapshot_map: Dict[str, str],
) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for path_str, meta in baseline_data.items():
        current = Path(path_str)
        baseline_hash = str(meta.get("sha256", ""))
        baseline_size = int(meta.get("size", 0))
        baseline_owner = str(meta.get("owner", "unknown"))
        snap_str = snapshot_map.get(path_str, "")
        snap_path = Path(snap_str) if snap_str else None
        snap_ok = bool(snap_path and snap_path.exists())

        if not current.exists():
            rows.append(
                {
                    "path": path_str,
                    "exists_now": False,
                    "hash_status": "Deleted",
                    "baseline_hash": baseline_hash,
                    "current_hash": "MISSING",
                    "baseline_size": baseline_size,
                    "current_size": 0,
                    "baseline_owner": baseline_owner,
                    "current_owner": "N/A",
                    "size_deviation_bytes": -baseline_size,
                    "size_deviation_percent": 100.0 if baseline_size > 0 else 0.0,
                    "content_deviation_percent": 100.0,
                    "status": "Anomaly",
                    "change_reasons": "File deleted",
                }
            )
            continue

        try:
            import pwd

            stat = current.stat()
            try:
                current_owner = pwd.getpwuid(stat.st_uid).pw_name
            except Exception:
                current_owner = str(stat.st_uid)

            current_hash = sha256_file(current)
            current_size = stat.st_size
            verified = current_hash == baseline_hash

            size_dev_bytes = current_size - baseline_size
            size_dev_pct = (
                (abs(size_dev_bytes) / baseline_size * 100.0)
                if baseline_size > 0
                else (0.0 if current_size == 0 else 100.0)
            )
            content_dev_pct = (
                content_deviation_percent(snap_path, current)
                if snap_ok
                else (0.0 if verified else 100.0)
            )

            reasons: List[str] = []
            if not verified:
                reasons.append("Hash mismatch")
            if size_dev_bytes != 0:
                reasons.append(f"Size changed by {human_bytes(size_dev_bytes)}")
            if current_owner != baseline_owner:
                reasons.append(f"Owner changed: {baseline_owner} → {current_owner}")
            if content_dev_pct > 0:
                reasons.append(f"Content deviation: {content_dev_pct:.2f}%")

            rows.append(
                {
                    "path": path_str,
                    "exists_now": True,
                    "hash_status": "Verified" if verified else "Mismatch",
                    "baseline_hash": baseline_hash,
                    "current_hash": current_hash,
                    "baseline_size": baseline_size,
                    "current_size": current_size,
                    "baseline_owner": baseline_owner,
                    "current_owner": current_owner,
                    "size_deviation_bytes": size_dev_bytes,
                    "size_deviation_percent": round(size_dev_pct, 4),
                    "content_deviation_percent": round(content_dev_pct, 4),
                    "status": "Normal" if verified else "Anomaly",
                    "change_reasons": "; ".join(reasons) if reasons else "None",
                }
            )
        except Exception as exc:
            rows.append(
                {
                    "path": path_str,
                    "exists_now": True,
                    "hash_status": "Unreadable",
                    "baseline_hash": baseline_hash,
                    "current_hash": "ERROR",
                    "baseline_size": baseline_size,
                    "current_size": 0,
                    "baseline_owner": baseline_owner,
                    "current_owner": "ERROR",
                    "size_deviation_bytes": -baseline_size,
                    "size_deviation_percent": 100.0 if baseline_size > 0 else 0.0,
                    "content_deviation_percent": 100.0,
                    "status": "Anomaly",
                    "change_reasons": f"Read error: {exc}",
                }
            )
    return pd.DataFrame(rows)


def style_table(df: pd.DataFrame) -> pd.io.formats.style.Styler:
    def row_style(row: pd.Series) -> List[str]:
        if row.get("status") == "Anomaly":
            return ["background-color: #ffebee; color: #b71c1c;" for _ in row]
        return ["background-color: #e8f5e9; color: #1b5e20;" for _ in row]

    return df.style.apply(row_style, axis=1)


# ---------------------------------------------------------------------------
# Inline anomaly chart (red/green stacked bar)
# ---------------------------------------------------------------------------


def render_anomaly_chart(df: pd.DataFrame) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.patches as mpatches
        import matplotlib.pyplot as plt
    except ImportError:
        st.warning("matplotlib not installed — cannot render inline chart.")
        return

    if df.empty:
        st.info("No data to chart.")
        return

    normal_df = df[df["status"] == "Normal"]
    anomaly_df = df[df["status"] == "Anomaly"]

    # --- Bar 1: file counts ---
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    fig.patch.set_facecolor("#0e1117")
    for ax in axes:
        ax.set_facecolor("#0e1117")
        ax.tick_params(colors="white")
        ax.xaxis.label.set_color("white")
        ax.yaxis.label.set_color("white")
        ax.title.set_color("white")
        for spine in ax.spines.values():
            spine.set_edgecolor("#444")

    # Subplot 1 — Normal vs Anomaly file count
    ax = axes[0]
    labels = ["Normal", "Anomaly"]
    counts = [len(normal_df), len(anomaly_df)]
    colors = ["#2ca02c", "#d62728"]
    bars = ax.bar(labels, counts, color=colors, edgecolor="#222", linewidth=1.2)
    for bar, count in zip(bars, counts):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.1,
            str(count),
            ha="center",
            va="bottom",
            color="white",
            fontsize=12,
            fontweight="bold",
        )
    ax.set_title("File Status Count", fontsize=13, fontweight="bold")
    ax.set_ylabel("Files")

    # Subplot 2 — Content deviation % per anomaly file
    ax2 = axes[1]
    if not anomaly_df.empty:
        names = [Path(p).name for p in anomaly_df["path"]]
        devs = anomaly_df["content_deviation_percent"].tolist()
        bar_colors = ["#d62728" if d > 50 else "#ff7f0e" for d in devs]
        b2 = ax2.barh(names, devs, color=bar_colors, edgecolor="#222")
        ax2.set_xlabel("Content Deviation %")
        ax2.set_title(
            "Content Deviation (Anomaly Files)", fontsize=13, fontweight="bold"
        )
        ax2.set_xlim(0, 105)
        for bar, val in zip(b2, devs):
            ax2.text(
                min(val + 1, 103),
                bar.get_y() + bar.get_height() / 2,
                f"{val:.1f}%",
                va="center",
                color="white",
                fontsize=9,
            )
    else:
        ax2.text(
            0.5,
            0.5,
            "No Anomaly Files",
            ha="center",
            va="center",
            color="white",
            fontsize=14,
        )
        ax2.axis("off")

    # Subplot 3 — Size deviation % per anomaly file
    ax3 = axes[2]
    if not anomaly_df.empty:
        names3 = [Path(p).name for p in anomaly_df["path"]]
        size_devs = anomaly_df["size_deviation_percent"].tolist()
        bar_colors3 = ["#d62728" if d > 50 else "#ff7f0e" for d in size_devs]
        b3 = ax3.barh(names3, size_devs, color=bar_colors3, edgecolor="#222")
        ax3.set_xlabel("Size Deviation %")
        ax3.set_title("Size Deviation (Anomaly Files)", fontsize=13, fontweight="bold")
        ax3.set_xlim(0, max(max(size_devs) * 1.15, 10))
        for bar, val in zip(b3, size_devs):
            ax3.text(
                val + 0.5,
                bar.get_y() + bar.get_height() / 2,
                f"{val:.1f}%",
                va="center",
                color="white",
                fontsize=9,
            )
    else:
        ax3.text(
            0.5,
            0.5,
            "No Anomaly Files",
            ha="center",
            va="center",
            color="white",
            fontsize=14,
        )
        ax3.axis("off")

    normal_patch = mpatches.Patch(color="#2ca02c", label="Normal")
    anomaly_patch = mpatches.Patch(color="#d62728", label="Anomaly")
    orange_patch = mpatches.Patch(color="#ff7f0e", label="Moderate (<50%)")
    fig.legend(
        handles=[normal_patch, anomaly_patch, orange_patch],
        loc="lower center",
        ncol=3,
        facecolor="#0e1117",
        labelcolor="white",
        fontsize=10,
        framealpha=0.5,
    )

    fig.tight_layout(rect=[0, 0.06, 1, 1])
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", facecolor=fig.get_facecolor())
    buf.seek(0)
    st.image(buf, use_container_width=True)
    import matplotlib.pyplot as plt2

    plt2.close(fig)


# ---------------------------------------------------------------------------
# Sidebar config
# ---------------------------------------------------------------------------


def build_config_from_sidebar() -> MonitorConfig:
    with st.sidebar:
        st.header("Monitor Configuration")
        directory = st.text_input("Watched directory", value=CONFIG.directory)
        baseline = st.text_input("Baseline file", value=CONFIG.baseline)
        alert_log = st.text_input("Alert log", value=CONFIG.alert_log)
        report_dir = st.text_input("Report directory", value=CONFIG.report_dir)
        snapshot_dir = st.text_input("Snapshot directory", value="./baseline_snapshots")
        interval = st.number_input(
            "Polling interval (s)", min_value=5, value=CONFIG.interval
        )
        working_hours = st.text_input(
            "Working hours (HH:MM-HH:MM)", value=CONFIG.working_hours
        )
        authorized_users = st.text_input(
            "Authorized users (comma-separated)",
            value=",".join(CONFIG.authorized_users),
        )
        frequency_threshold = st.number_input(
            "Frequency threshold", min_value=1, value=CONFIG.frequency_threshold
        )
        frequency_window = st.number_input(
            "Frequency window (s)", min_value=30, value=CONFIG.frequency_window
        )
        size_change_limit = st.number_input(
            "Size change limit (bytes)", min_value=0, value=CONFIG.size_change_limit
        )
        risk_threshold = st.number_input(
            "Risk threshold", min_value=1, value=CONFIG.risk_threshold
        )
        enable_reports = st.checkbox(
            "Enable saved reports", value=CONFIG.enable_reports
        )

        st.divider()
        st.subheader("Auto Refresh")
        auto_refresh = st.checkbox("Auto refresh", value=False)
        refresh_seconds = st.number_input(
            "Refresh every (s)", min_value=2, max_value=300, value=10, step=1
        )

    st.session_state["snapshot_dir"] = snapshot_dir
    st.session_state["auto_refresh"] = auto_refresh
    st.session_state["refresh_seconds"] = int(refresh_seconds)

    return MonitorConfig(
        directory=directory,
        baseline=baseline,
        alert_log=alert_log,
        report_dir=report_dir,
        interval=int(interval),
        working_hours=working_hours,
        authorized_users=[u.strip() for u in authorized_users.split(",") if u.strip()],
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    st.set_page_config(page_title="AI Rule-Based FIM", layout="wide")
    st.title("AI Rule-Based File Integrity Monitoring Dashboard")
    st.caption(
        "Real-time monitoring · Hash verification · Deviation analysis · Anomaly detection"
    )

    config = build_config_from_sidebar()

    try:
        monitor = build_monitor(config)
    except RuntimeError as exc:
        if "matplotlib" in str(exc):
            st.warning("matplotlib not installed — saved PNG reports disabled.")
            config.enable_reports = False
            monitor = build_monitor(config)
        else:
            raise

    # ---- Action bar --------------------------------------------------------
    act1, act2, act3, act4 = st.columns([1, 1, 2, 1])
    with act1:
        if st.button("Run one iteration", type="primary", use_container_width=True):
            with st.spinner("Running monitor..."):
                monitor.run_once()
            st.success("Iteration completed.")
    with act3:
        approve_path = st.text_input(
            "Approve file path (updates baseline)",
            label_visibility="collapsed",
            placeholder="Enter file path to approve...",
        )
        if st.button("Approve change", use_container_width=True):
            if approve_path.strip():
                monitor.approve_change(Path(approve_path).expanduser().resolve())
                st.success("Baseline updated.")
            else:
                st.warning("Enter a file path.")
    with act4:
        if st.button("Refresh now", use_container_width=True):
            st.rerun()

    with act2:
        if st.button("Initialize baseline", use_container_width=True):
            with st.spinner("Initializing..."):
                monitor.initialize()
            st.success("Baseline initialized.")

    st.divider()

    # ---- Paths -------------------------------------------------------------
    watched_dir = Path(config.directory).expanduser().resolve()
    baseline_path = Path(config.baseline).expanduser().resolve()
    alert_log_path = Path(config.alert_log).expanduser().resolve()
    report_dir = Path(config.report_dir).expanduser().resolve()
    snapshot_dir = (
        Path(st.session_state.get("snapshot_dir", "./baseline_snapshots"))
        .expanduser()
        .resolve()
    )

    # ---- Data loading -------------------------------------------------------
    dir_stats = collect_directory_stats(watched_dir)
    baseline_stats = load_baseline_stats(baseline_path)
    alerts = load_alerts(alert_log_path)
    baseline_data = load_baseline_data(baseline_path)
    snapshot_map = ensure_snapshots(baseline_data, snapshot_dir)
    df_integrity = analyze_integrity(baseline_data, snapshot_map)

    if df_integrity.empty:
        verified_count = anomaly_count = 0
        avg_content_dev = avg_size_dev = 0.0
    else:
        verified_count = int((df_integrity["hash_status"] == "Verified").sum())
        anomaly_count = int((df_integrity["status"] == "Anomaly").sum())
        avg_content_dev = float(df_integrity["content_deviation_percent"].mean())
        avg_size_dev = float(df_integrity["size_deviation_percent"].mean())

    # ---- Metric cards -------------------------------------------------------
    st.subheader("Overview Metrics")
    m = st.columns(10)
    m[0].metric("Watched Files", f"{dir_stats['files']:,}")
    m[1].metric("Watched Size", human_bytes(dir_stats["size"]))
    m[2].metric("Baseline Files", f"{baseline_stats['files']:,}")
    m[3].metric("Baseline Size", human_bytes(baseline_stats["size"]))
    m[4].metric("Total Alerts", f"{len(alerts):,}")
    m[5].metric("Hash Verified", f"{verified_count:,}")
    m[6].metric("Anomaly Files", f"{anomaly_count:,}")
    m[7].metric("Avg Content Dev", f"{avg_content_dev:.2f}%")
    m[8].metric("Avg Size Dev", f"{avg_size_dev:.2f}%")
    m[9].metric("Size Delta", human_bytes(dir_stats["size"] - baseline_stats["size"]))

    st.divider()

    # ---- Inline anomaly chart -----------------------------------------------
    st.subheader("Live Anomaly Chart")
    if not df_integrity.empty:
        render_anomaly_chart(df_integrity)
    else:
        st.info("No integrity data to chart yet. Initialize baseline first.")

    st.divider()

    # ---- Full integrity table -----------------------------------------------
    display_cols = [
        "path",
        "hash_status",
        "baseline_hash",
        "current_hash",
        "baseline_size",
        "current_size",
        "baseline_owner",
        "current_owner",
        "size_deviation_bytes",
        "size_deviation_percent",
        "content_deviation_percent",
        "status",
        "change_reasons",
    ]

    st.subheader("Hash Verification + Full Deviation Table")
    if df_integrity.empty:
        st.info("No baseline entries found. Initialize baseline and run an iteration.")
    else:
        st.dataframe(style_table(df_integrity[display_cols]), use_container_width=True)

    st.divider()

    # ---- Normal / Anomaly split ---------------------------------------------
    if not df_integrity.empty:
        normal_df = df_integrity[df_integrity["status"] == "Normal"].copy()
        anomaly_df = df_integrity[df_integrity["status"] == "Anomaly"].copy()

        left, right = st.columns(2)

        with left:
            st.markdown("### Normal Files")
            if normal_df.empty:
                st.info("No normal files found.")
            else:
                st.success(
                    f"{len(normal_df)} file(s) intact — hash verified, no changes detected."
                )
                st.dataframe(
                    style_table(normal_df[display_cols]), use_container_width=True
                )
                st.download_button(
                    "Download Normal Files CSV",
                    data=normal_df.to_csv(index=False),
                    file_name="normal_files.csv",
                    mime="text/csv",
                )

        with right:
            st.markdown("### Anomaly Files")
            if anomaly_df.empty:
                st.success("No anomaly files detected.")
            else:
                st.error(f"{len(anomaly_df)} anomaly file(s) detected!")
                st.dataframe(
                    style_table(anomaly_df[display_cols]), use_container_width=True
                )
                st.download_button(
                    "Download Anomaly Files CSV",
                    data=anomaly_df.to_csv(index=False),
                    file_name="anomaly_files.csv",
                    mime="text/csv",
                )

    st.divider()

    # ---- Modification error log ---------------------------------------------
    st.subheader("Modification Error Log")
    if df_integrity.empty:
        st.info("No data yet.")
    else:
        changed_df = df_integrity[df_integrity["change_reasons"] != "None"].copy()
        if changed_df.empty:
            st.success("No modifications detected — all files match baseline.")
        else:
            for _, row in changed_df.iterrows():
                with st.expander(
                    f"[{'ANOMALY' if row['status'] == 'Anomaly' else 'CHANGED'}] {Path(row['path']).name}  --  {row['change_reasons'][:80]}",
                    expanded=(row["status"] == "Anomaly"),
                ):
                    ecol1, ecol2, ecol3 = st.columns(3)
                    ecol1.markdown(f"**Path:** `{row['path']}`")
                    ecol2.markdown(f"**Status:** `{row['status']}`")
                    ecol3.markdown(f"**Hash Status:** `{row['hash_status']}`")

                    hcol1, hcol2 = st.columns(2)
                    hcol1.code(f"Baseline hash:\n{row['baseline_hash']}", language=None)
                    hcol2.code(f"Current hash:\n{row['current_hash']}", language=None)

                    dcol1, dcol2, dcol3, dcol4 = st.columns(4)
                    dcol1.metric(
                        "Baseline Size", human_bytes(int(row["baseline_size"]))
                    )
                    dcol2.metric("Current Size", human_bytes(int(row["current_size"])))
                    dcol3.metric(
                        "Size Deviation", f"{row['size_deviation_percent']:.2f}%"
                    )
                    dcol4.metric(
                        "Content Deviation", f"{row['content_deviation_percent']:.2f}%"
                    )

                    if row["baseline_owner"] != row["current_owner"]:
                        st.warning(
                            f"Owner changed: **{row['baseline_owner']}** → **{row['current_owner']}**"
                        )

                    st.markdown(f"**All change reasons:** {row['change_reasons']}")

    st.divider()

    # ---- Alerts summary -----------------------------------------------------
    st.subheader("Alerts Summary")
    if alerts:
        counts = Counter(a.get("event_type", "Unknown") for a in alerts)
        st.bar_chart(pd.DataFrame.from_dict(counts, orient="index", columns=["Count"]))

        rule_hits: Counter[str] = Counter()
        for a in alerts:
            for rule in a.get("triggered_rules", []):
                rule_hits[rule] += 1
        if rule_hits:
            st.markdown("**Top triggered rules:**")
            rc1, rc2 = st.columns(2)
            rc1.bar_chart(
                pd.DataFrame.from_dict(rule_hits, orient="index", columns=["Hits"])
            )

        recent_alerts = load_alerts(alert_log_path, limit=50)
        st.dataframe(pd.DataFrame(recent_alerts), use_container_width=True)
        st.caption(f"Total alerts on record: {len(alerts):,}")
    else:
        st.info("No alerts recorded yet.")

    st.divider()

    # ---- Saved anomaly report images ----------------------------------------
    st.subheader("Anomaly Report Images")
    if not config.enable_reports:
        st.info(
            "Saved reports are disabled. Enable them in the sidebar and install matplotlib."
        )
    else:
        reports = list_reports(report_dir)
        if not reports:
            st.warning("No report images found. Run an iteration to generate one.")
        else:
            st.success(f"{len(reports)} report image(s) found. Showing latest 6.")
            for rp in reports[:6]:
                st.image(str(rp), caption=rp.name, use_container_width=True)

    # ---- Auto refresh -------------------------------------------------------
    if st.session_state.get("auto_refresh", False):
        secs = st.session_state.get("refresh_seconds", 10)
        st.toast(f"Auto refresh in {secs}s...")
        time.sleep(secs)
        st.rerun()


if __name__ == "__main__":
    main()
