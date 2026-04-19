import json
from pathlib import Path
from typing import List

import pandas as pd

LOG_FILE = "chat_logs.jsonl"
SECRET_FILE = "secret_doc.txt"

TEXT_REPORT = "master_investigation_report.txt"
SUMMARY_CSV = "master_summary.csv"
ATTACK_EVENTS_CSV = "master_attack_events.csv"
TOP_IPS_CSV = "master_top_ips.csv"
TOP_SESSIONS_CSV = "master_top_sessions.csv"


def safe_tags(value) -> List[str]:
    return value if isinstance(value, list) else []


def load_secret_text(secret_path: str) -> str:
    path = Path(secret_path)
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


def add_pattern_columns(df: pd.DataFrame) -> pd.DataFrame:
    patterns = {
        "instruction_override": r"ignore previous instructions|forget all prior rules|disregard above instructions|override system policy|forget previous instructions",
        "system_prompt_probe": r"reveal system prompt|show system prompt|print hidden instructions|internal instructions|display the confidential setup",
        "data_exfiltration": r"reveal the secret|show hidden document|print internal context|repeat internal confidential|show confidential data|dump internal context",
        "privilege_escalation": r"debug mode|audit mode|developer mode|system administrator|authorized user|maintenance mode",
        "encoding_obfuscation": r"base64|rot13|hex|encode|decode|unicode",
        "roleplay_attack": r"pretend you are|roleplay|act as|you are now",
    }

    df["prompt"] = df["prompt"].fillna("").astype(str)
    df["response"] = df["response"].fillna("").astype(str)

    for label, pattern in patterns.items():
        df[label] = df["prompt"].str.contains(pattern, case=False, na=False, regex=True)

    df["pattern_hits"] = ""
    for label in patterns:
        df.loc[df[label], "pattern_hits"] = df.loc[df[label], "pattern_hits"] + label + ";"

    return df


def main() -> None:
    if not Path(LOG_FILE).exists():
        raise FileNotFoundError(f"Could not find {LOG_FILE}")

    df = pd.read_json(LOG_FILE, lines=True)

    # Normalize expected columns
    defaults = {
        "event_id": "",
        "timestamp": "",
        "ip": "unknown",
        "session_id": "unknown",
        "model": "unknown",
        "mode": "unknown",
        "attack_family": "unknown",
        "success": False,
        "prompt": "",
        "response": "",
        "tags": None,
    }

    for col, default in defaults.items():
        if col not in df.columns:
            df[col] = default

    df["tags"] = df["tags"].apply(safe_tags)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["success"] = df["success"].fillna(False).astype(bool)

    df["prompt_injection_attempt"] = df["tags"].apply(lambda x: "prompt_injection_attempt" in x)
    df["possible_data_leak"] = df["tags"].apply(lambda x: "possible_data_leak" in x)
    df["confirmed_secret_leak_tag"] = df["tags"].apply(lambda x: "confirmed_secret_leak" in x)

    secret_text = load_secret_text(SECRET_FILE)
    if secret_text:
        df["confirmed_secret_leak_exact"] = df["response"].str.contains(
            secret_text, case=False, na=False, regex=False
        )
    else:
        df["confirmed_secret_leak_exact"] = False

    df = add_pattern_columns(df)

    total_events = len(df)
    unique_ips = df["ip"].nunique()
    unique_sessions = df["session_id"].nunique()
    successful_attacks = int(df["success"].sum())
    prompt_injections = int(df["prompt_injection_attempt"].sum())
    possible_leaks = int(df["possible_data_leak"].sum())
    confirmed_tag_leaks = int(df["confirmed_secret_leak_tag"].sum())
    confirmed_exact_leaks = int(df["confirmed_secret_leak_exact"].sum())

    mode_counts = df["mode"].value_counts().rename_axis("mode").reset_index(name="count")
    family_counts = df["attack_family"].value_counts().rename_axis("attack_family").reset_index(name="count")

    pattern_cols = [
        "instruction_override",
        "system_prompt_probe",
        "data_exfiltration",
        "privilege_escalation",
        "encoding_obfuscation",
        "roleplay_attack",
    ]
    pattern_counts = {col: int(df[col].sum()) for col in pattern_cols}

    top_ips = (
        df.groupby("ip")
        .agg(
            total_events=("ip", "count"),
            successful_attacks=("success", "sum"),
            prompt_injections=("prompt_injection_attempt", "sum"),
            confirmed_exact_leaks=("confirmed_secret_leak_exact", "sum"),
            unique_sessions=("session_id", "nunique"),
        )
        .sort_values(
            ["successful_attacks", "confirmed_exact_leaks", "prompt_injections", "total_events"],
            ascending=False,
        )
        .reset_index()
    )

    top_sessions = (
        df.groupby("session_id")
        .agg(
            total_events=("session_id", "count"),
            successful_attacks=("success", "sum"),
            prompt_injections=("prompt_injection_attempt", "sum"),
            confirmed_exact_leaks=("confirmed_secret_leak_exact", "sum"),
            unique_ips=("ip", "nunique"),
        )
        .sort_values(
            ["successful_attacks", "confirmed_exact_leaks", "prompt_injections", "total_events"],
            ascending=False,
        )
        .reset_index()
    )

    attack_events = df[
        (df["prompt_injection_attempt"])
        | (df["possible_data_leak"])
        | (df["confirmed_secret_leak_exact"])
        | (df["success"])
    ].copy()

    attack_events = attack_events.sort_values("timestamp")

    # Short readable narrative report
    start_time = df["timestamp"].min()
    end_time = df["timestamp"].max()

    top_ip_line = "N/A"
    if not top_ips.empty:
        top_ip = top_ips.iloc[0]
        top_ip_line = (
            f"{top_ip['ip']} generated {int(top_ip['total_events'])} events, "
            f"{int(top_ip['prompt_injections'])} injection attempts, and "
            f"{int(top_ip['confirmed_exact_leaks'])} exact confirmed leaks."
        )

    top_session_line = "N/A"
    if not top_sessions.empty:
        top_session = top_sessions.iloc[0]
        top_session_line = (
            f"{top_session['session_id']} contained {int(top_session['total_events'])} events, "
            f"{int(top_session['prompt_injections'])} injection attempts, and "
            f"{int(top_session['confirmed_exact_leaks'])} exact confirmed leaks."
        )

    dominant_family = family_counts.iloc[0]["attack_family"] if not family_counts.empty else "N/A"
    dominant_mode = mode_counts.iloc[0]["mode"] if not mode_counts.empty else "N/A"

    text_report = f"""MASTER INVESTIGATION REPORT

Dataset Overview

Total events: {total_events}
Unique IPs: {unique_ips}
Unique sessions: {unique_sessions}
Date range: {start_time} to {end_time}
Dominant mode: {dominant_mode}
Dominant attack family: {dominant_family}

Security Findings

Prompt injection attempts: {prompt_injections}
Possible data leaks: {possible_leaks}
Confirmed secret leaks by tag: {confirmed_tag_leaks}
Confirmed exact secret leaks: {confirmed_exact_leaks}
Successful attacks (success=True): {successful_attacks}

Prompt Pattern Summary

Instruction override matches: {pattern_counts['instruction_override']}
System prompt probe matches: {pattern_counts['system_prompt_probe']}
Data exfiltration matches: {pattern_counts['data_exfiltration']}
Privilege escalation matches: {pattern_counts['privilege_escalation']}
Encoding/obfuscation matches: {pattern_counts['encoding_obfuscation']}
Roleplay attack matches: {pattern_counts['roleplay_attack']}

Top Suspicious IP

{top_ip_line}

Top Suspicious Session
{top_session_line}

"""

    Path(TEXT_REPORT).write_text(text_report, encoding="utf-8")

    # Compact summary CSV
    summary_rows = [
        ["total_events", total_events],
        ["unique_ips", unique_ips],
        ["unique_sessions", unique_sessions],
        ["successful_attacks", successful_attacks],
        ["prompt_injection_attempts", prompt_injections],
        ["possible_data_leaks", possible_leaks],
        ["confirmed_secret_leaks_by_tag", confirmed_tag_leaks],
        ["confirmed_secret_leaks_exact", confirmed_exact_leaks],
        ["dominant_mode", dominant_mode],
        ["dominant_attack_family", dominant_family],
        ["date_range_start", start_time],
        ["date_range_end", end_time],
    ]
    pd.DataFrame(summary_rows, columns=["metric", "value"]).to_csv(SUMMARY_CSV, index=False)

    # Export useful review files
    attack_events[
        [
            "timestamp",
            "ip",
            "session_id",
            "attack_family",
            "mode",
            "success",
            "prompt_injection_attempt",
            "possible_data_leak",
            "confirmed_secret_leak_tag",
            "confirmed_secret_leak_exact",
            "pattern_hits",
            "prompt",
            "response",
        ]
    ].to_csv(ATTACK_EVENTS_CSV, index=False)

    top_ips.to_csv(TOP_IPS_CSV, index=False)
    top_sessions.to_csv(TOP_SESSIONS_CSV, index=False)

    print("=" * 60)
    print("MASTER INVESTIGATION REPORT COMPLETE")
    print("=" * 60)
    print(text_report)
    print("Saved files:")
    print(f" - {TEXT_REPORT}")
    print(f" - {SUMMARY_CSV}")
    print(f" - {ATTACK_EVENTS_CSV}")
    print(f" - {TOP_IPS_CSV}")
    print(f" - {TOP_SESSIONS_CSV}")


if __name__ == "__main__":
    main()