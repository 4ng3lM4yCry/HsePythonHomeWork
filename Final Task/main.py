from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List

import matplotlib.pyplot as plt
import pandas as pd
import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"
DEFAULT_LOG_FILE = "alerts-only.json"
DEFAULT_REPORT_FILE = "threat_report.csv"
DEFAULT_CHART_FILE = "threat_chart.png"

# Пороговые значения и веса вынесены в константы,
# чтобы их было проще менять и объяснять.
RISK_HIGH_THRESHOLD = 55
RISK_MEDIUM_THRESHOLD = 28

RISK_ALERT_WEIGHT = 3
RISK_SEVERITY_WEIGHT = 10
RISK_SIGNATURE_WEIGHT = 2
RISK_VT_MALICIOUS_WEIGHT = 6
RISK_VT_SUSPICIOUS_WEIGHT = 3
RISK_NEGATIVE_REPUTATION_WEIGHT = 0.5

DEFAULT_VT_MAX_IPS = 8
DEFAULT_VT_TIMEOUT = 20
DEFAULT_VT_SLEEP_SECONDS = 0.0
DEFAULT_VT_RETRIES = 2
DEFAULT_VT_RETRY_DELAY = 1.5


@dataclass
class VTResult:
    ip: str
    vt_lookup_status: str
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_undetected: int = 0
    vt_reputation: int = 0
    vt_country: str = ""
    vt_as_owner: str = ""
    vt_network: str = ""
    vt_tags: str = ""
    vt_error: str = ""


def setup_logging() -> None:
    """Настройка простого логирования в консоль."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )


def get_env_str(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    return raw if raw else default


def get_env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        logging.warning(
            "Переменная окружения %s содержит некорректное целое значение %r. "
            "Используется значение по умолчанию: %s",
            name,
            raw,
            default,
        )
        return default


def get_env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        logging.warning(
            "Переменная окружения %s содержит некорректное вещественное значение %r. "
            "Используется значение по умолчанию: %s",
            name,
            raw,
            default,
        )
        return default


def get_env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip().lower()
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    logging.warning(
        "Переменная окружения %s содержит некорректное булево значение %r. "
        "Используется значение по умолчанию: %s",
        name,
        raw,
        default,
    )
    return default


def load_env_file(env_path: str = ".env") -> None:
    path = Path(env_path)
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Автоматизированный анализ Suricata + VirusTotal"
    )
    parser.add_argument(
        "--log-file",
        default=get_env_str("SURICATA_LOG_PATH", DEFAULT_LOG_FILE),
        help="Путь к JSON-файлу с alert-логами Suricata",
    )
    parser.add_argument(
        "--report-file",
        default=get_env_str("REPORT_FILE", DEFAULT_REPORT_FILE),
        help="Имя итогового CSV-отчёта",
    )
    parser.add_argument(
        "--chart-file",
        default=get_env_str("CHART_FILE", DEFAULT_CHART_FILE),
        help="Имя PNG-файла с графиком",
    )
    parser.add_argument(
        "--top-ip-count",
        type=int,
        default=get_env_int("VT_MAX_IPS", DEFAULT_VT_MAX_IPS),
        help="Сколько IP проверять через VirusTotal",
    )
    parser.add_argument(
        "--request-timeout",
        type=int,
        default=get_env_int("VT_TIMEOUT", DEFAULT_VT_TIMEOUT),
        help="Таймаут HTTP-запроса в секундах",
    )
    parser.add_argument(
        "--sleep-seconds",
        type=float,
        default=get_env_float("VT_SLEEP_SECONDS", DEFAULT_VT_SLEEP_SECONDS),
        help="Пауза между запросами к VT",
    )
    parser.add_argument(
        "--vt-retries",
        type=int,
        default=get_env_int("VT_RETRIES", DEFAULT_VT_RETRIES),
        help="Количество повторных попыток запроса к VirusTotal",
    )
    parser.add_argument(
        "--vt-retry-delay",
        type=float,
        default=get_env_float("VT_RETRY_DELAY", DEFAULT_VT_RETRY_DELAY),
        help="Задержка между повторными попытками запроса к VirusTotal",
    )
    parser.add_argument(
        "--use-mock-vt",
        action="store_true",
        help="Не ходить в реальный VirusTotal, а использовать демонстрационные данные",
    )
    return parser.parse_args()


def is_global_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def read_suricata_alerts(log_file: str) -> pd.DataFrame:
    path = Path(log_file)
    if not path.exists():
        raise FileNotFoundError(f"Файл логов не найден: {path}")

    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, list):
        raise ValueError("Ожидался JSON-массив с alert-событиями Suricata")

    rows: List[Dict[str, Any]] = []
    for event in data:
        alert = event.get("alert", {})
        rows.append(
            {
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip", ""),
                "src_port": event.get("src_port"),
                "dest_ip": event.get("dest_ip", ""),
                "dest_port": event.get("dest_port"),
                "proto": event.get("proto", ""),
                "signature": alert.get("signature", "Unknown"),
                "category": alert.get("category", "Unknown"),
                "severity": alert.get("severity", 3),
                "action": alert.get("action", "unknown"),
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        raise ValueError("Логи загружены, но alert-события отсутствуют")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["severity"] = pd.to_numeric(df["severity"], errors="coerce").fillna(3).astype(int)
    return df


def extract_candidate_ips(df: pd.DataFrame) -> pd.DataFrame:
    records: List[Dict[str, Any]] = []

    for row in df.to_dict(orient="records"):
        src_ip = row["src_ip"]
        dest_ip = row["dest_ip"]

        base_record = {
            "timestamp": row["timestamp"],
            "signature": row["signature"],
            "category": row["category"],
            "severity": row["severity"],
            "proto": row["proto"],
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_port": row["src_port"],
            "dest_port": row["dest_port"],
            "action": row["action"],
        }

        if is_global_ip(src_ip):
            records.append(
                {
                    "candidate_ip": src_ip,
                    "direction": "inbound",
                    "local_peer": dest_ip,
                    **base_record,
                }
            )

        if is_global_ip(dest_ip):
            records.append(
                {
                    "candidate_ip": dest_ip,
                    "direction": "outbound",
                    "local_peer": src_ip,
                    **base_record,
                }
            )

    candidate_df = pd.DataFrame(records)
    if candidate_df.empty:
        raise ValueError(
            "В логах не найдено ни одного внешнего IP-адреса для анализа."
        )
    return candidate_df


def most_common_string(values: Iterable[str]) -> str:
    series = pd.Series(list(values), dtype="object")
    if series.empty:
        return ""
    mode = series.mode()
    return str(mode.iloc[0]) if not mode.empty else str(series.iloc[0])


def summarize_candidates(candidate_df: pd.DataFrame) -> pd.DataFrame:
    grouped_rows: List[Dict[str, Any]] = []

    for ip, group in candidate_df.groupby("candidate_ip", sort=False):
        directions = ", ".join(
            sorted(group["direction"].dropna().astype(str).unique().tolist())
        )
        top_local_peers = (
            group["local_peer"].astype(str).value_counts().head(3).index.tolist()
        )

        grouped_rows.append(
            {
                "ip": ip,
                "alert_count": int(len(group)),
                "directions": directions,
                "unique_signatures": int(group["signature"].nunique()),
                "unique_categories": int(group["category"].nunique()),
                "critical_severity": int(group["severity"].min()),
                "top_signature": most_common_string(group["signature"].tolist()),
                "top_category": most_common_string(group["category"].tolist()),
                "top_local_peers": ", ".join(top_local_peers),
                "first_seen": group["timestamp"].min(),
                "last_seen": group["timestamp"].max(),
            }
        )

    summary_df = pd.DataFrame(grouped_rows)
    if summary_df.empty:
        raise ValueError("Не удалось агрегировать подозрительные IP-адреса.")

    summary_df = summary_df.sort_values(
        by=["alert_count", "critical_severity", "unique_signatures"],
        ascending=[False, True, False],
    ).reset_index(drop=True)

    return summary_df


MOCK_VT_DATA: Dict[str, VTResult] = {
    "64.135.77.30": VTResult("64.135.77.30", "mock", 7, 2, 9, 60, -18, "US", "Example ISP", "64.135.77.0/24", "scan,ssh"),
    "217.182.164.10": VTResult("217.182.164.10", "mock", 5, 1, 12, 58, -10, "FR", "OVH SAS", "217.182.160.0/19", "scanner"),
    "134.119.3.164": VTResult("134.119.3.164", "mock", 3, 1, 15, 57, -6, "DE", "Host Europe GmbH", "134.119.0.0/16", "web"),
    "216.239.34.21": VTResult("216.239.34.21", "mock", 0, 0, 45, 20, 5, "US", "Google LLC", "216.239.32.0/19", "cdn"),
    "204.11.50.131": VTResult("204.11.50.131", "mock", 4, 1, 10, 61, -9, "US", "Example Transit", "204.11.50.0/24", "malware"),
    "5.9.158.75": VTResult("5.9.158.75", "mock", 6, 2, 8, 52, -14, "DE", "Hetzner Online", "5.9.0.0/16", "scan,botnet"),
}


def get_mock_vt_result(ip: str) -> VTResult:
    return MOCK_VT_DATA.get(ip, VTResult(ip=ip, vt_lookup_status="mock"))


def query_virustotal_ip(
    ip: str,
    api_key: str,
    timeout: int = DEFAULT_VT_TIMEOUT,
    retries: int = DEFAULT_VT_RETRIES,
    retry_delay: float = DEFAULT_VT_RETRY_DELAY,
) -> VTResult:
    headers = {"x-apikey": api_key}
    url = f"{VT_BASE_URL}/{ip}"

    for attempt in range(retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
        except requests.RequestException as exc:
            if attempt < retries:
                time.sleep(retry_delay)
                continue
            return VTResult(ip=ip, vt_lookup_status="request_error", vt_error=str(exc))

        if response.status_code == 200:
            try:
                payload = response.json()
            except json.JSONDecodeError:
                return VTResult(
                    ip=ip,
                    vt_lookup_status="invalid_json",
                    vt_error="Response is not valid JSON",
                )

            attributes = payload.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            tags = attributes.get("tags", []) or []

            return VTResult(
                ip=ip,
                vt_lookup_status="ok",
                vt_malicious=int(stats.get("malicious", 0) or 0),
                vt_suspicious=int(stats.get("suspicious", 0) or 0),
                vt_harmless=int(stats.get("harmless", 0) or 0),
                vt_undetected=int(stats.get("undetected", 0) or 0),
                vt_reputation=int(attributes.get("reputation", 0) or 0),
                vt_country=str(attributes.get("country", "") or ""),
                vt_as_owner=str(attributes.get("as_owner", "") or ""),
                vt_network=str(attributes.get("network", "") or ""),
                vt_tags=", ".join(map(str, tags[:5])),
            )

        if response.status_code == 404:
            return VTResult(
                ip=ip,
                vt_lookup_status="not_found",
                vt_error="IP отсутствует в VirusTotal",
            )

        if response.status_code == 401:
            return VTResult(
                ip=ip,
                vt_lookup_status="unauthorized",
                vt_error="Неверный API-ключ VirusTotal",
            )

        if response.status_code == 429:
            if attempt < retries:
                time.sleep(retry_delay)
                continue
            return VTResult(
                ip=ip,
                vt_lookup_status="rate_limited",
                vt_error="Превышен лимит запросов VirusTotal",
            )

        if 500 <= response.status_code < 600 and attempt < retries:
            time.sleep(retry_delay)
            continue

        error_text = response.text[:200].replace("\n", " ")
        return VTResult(
            ip=ip,
            vt_lookup_status=f"http_{response.status_code}",
            vt_error=error_text,
        )

    return VTResult(
        ip=ip,
        vt_lookup_status="unknown_error",
        vt_error="Неизвестная ошибка при запросе к VirusTotal",
    )


def enrich_with_virustotal(
    summary_df: pd.DataFrame,
    api_key: str,
    top_ip_count: int,
    timeout: int,
    sleep_seconds: float,
    use_mock_vt: bool,
    retries: int,
    retry_delay: float,
) -> pd.DataFrame:
    vt_rows: List[Dict[str, Any]] = []

    lookup_targets = summary_df.head(top_ip_count)["ip"].tolist()
    for ip in lookup_targets:
        if use_mock_vt:
            result = get_mock_vt_result(ip)
        else:
            result = query_virustotal_ip(
                ip=ip,
                api_key=api_key,
                timeout=timeout,
                retries=retries,
                retry_delay=retry_delay,
            )

        vt_rows.append(result.__dict__)

        if sleep_seconds > 0:
            time.sleep(sleep_seconds)

    if vt_rows:
        vt_df = pd.DataFrame(vt_rows)
    else:
        vt_df = pd.DataFrame(columns=list(VTResult("", "").__dict__.keys()))

    merged_df = summary_df.merge(vt_df, on="ip", how="left")

    fill_defaults = {
        "vt_lookup_status": "skipped",
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_harmless": 0,
        "vt_undetected": 0,
        "vt_reputation": 0,
        "vt_country": "",
        "vt_as_owner": "",
        "vt_network": "",
        "vt_tags": "",
        "vt_error": "",
    }

    for column, default_value in fill_defaults.items():
        merged_df[column] = merged_df[column].fillna(default_value)

    numeric_columns = [
        "vt_malicious",
        "vt_suspicious",
        "vt_harmless",
        "vt_undetected",
        "vt_reputation",
    ]
    for column in numeric_columns:
        merged_df[column] = pd.to_numeric(merged_df[column], errors="coerce").fillna(0)

    return merged_df


def classify_risk(score: float) -> str:
    if score >= RISK_HIGH_THRESHOLD:
        return "high"
    if score >= RISK_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def add_risk_metrics(df: pd.DataFrame) -> pd.DataFrame:

    severity_weight = (4 - df["critical_severity"].clip(lower=1, upper=3)).astype(int)
    negative_reputation = df["vt_reputation"].apply(
        lambda value: abs(value) if value < 0 else 0
    )

    df = df.copy()
    df["risk_score"] = (
        df["alert_count"] * RISK_ALERT_WEIGHT
        + severity_weight * RISK_SEVERITY_WEIGHT
        + df["unique_signatures"] * RISK_SIGNATURE_WEIGHT
        + df["vt_malicious"] * RISK_VT_MALICIOUS_WEIGHT
        + df["vt_suspicious"] * RISK_VT_SUSPICIOUS_WEIGHT
        + negative_reputation * RISK_NEGATIVE_REPUTATION_WEIGHT
    ).round(2)

    df["risk_level"] = df["risk_score"].apply(classify_risk)

    return df.sort_values(
        by=["risk_score", "alert_count"],
        ascending=[False, False],
    ).reset_index(drop=True)


def simulate_response(df: pd.DataFrame) -> None:
    logging.info("\n=== Реагирование на угрозы ===")

    high_df = df[df["risk_level"] == "high"]
    medium_df = df[df["risk_level"] == "medium"]

    if high_df.empty and medium_df.empty:
        logging.info("Подтверждённых угроз высокого/среднего уровня не найдено.")
        return

    for _, row in high_df.iterrows():
        logging.info(
            "[BLOCK] IP %s | score=%s | alerts=%s | VT malicious=%s",
            row["ip"],
            row["risk_score"],
            row["alert_count"],
            int(row["vt_malicious"]),
        )
        logging.info(
            "        Имитация блокировки IP %s и отправки уведомления SOC-команде.",
            row["ip"],
        )

    for _, row in medium_df.head(5).iterrows():
        logging.info(
            "[NOTIFY] IP %s | score=%s | top_signature=%s",
            row["ip"],
            row["risk_score"],
            row["top_signature"],
        )
        logging.info(
            "         Имитация уведомления аналитика о проверке IP %s.",
            row["ip"],
        )


def save_report(df: pd.DataFrame, report_file: str) -> None:
    export_df = df.copy()
    for column in ["first_seen", "last_seen"]:
        export_df[column] = export_df[column].astype(str)

    export_df.to_csv(report_file, index=False, encoding="utf-8-sig")
    logging.info("\n[OK] CSV-отчёт сохранён: %s", report_file)


def build_chart(df: pd.DataFrame, chart_file: str) -> None:
    top_df = df.head(5).copy()
    if top_df.empty:
        raise ValueError("Нет данных для построения графика.")

    plt.figure(figsize=(11, 6))
    plt.barh(top_df["ip"], top_df["risk_score"])
    plt.xlabel("Risk score")
    plt.ylabel("IP address")
    plt.title("Top-5 подозрительных IP по итоговому risk score")
    plt.gca().invert_yaxis()

    for index, value in enumerate(top_df["risk_score"]):
        plt.text(value + 0.5, index, f"{value}", va="center")

    plt.tight_layout()
    plt.savefig(chart_file, dpi=150)
    plt.close()
    logging.info("[OK] PNG-график сохранён: %s", chart_file)


def print_summary(df: pd.DataFrame) -> None:
    logging.info("=== Краткая сводка ===")
    logging.info("Всего внешних IP в отчёте: %s", len(df))
    logging.info("High risk: %s", int((df["risk_level"] == "high").sum()))
    logging.info("Medium risk: %s", int((df["risk_level"] == "medium").sum()))
    logging.info("Low risk: %s", int((df["risk_level"] == "low").sum()))

    logging.info("\nТоп-5 IP:")
    preview_columns = [
        "ip",
        "alert_count",
        "vt_malicious",
        "risk_score",
        "risk_level",
        "top_signature",
    ]
    logging.info("\n%s", df[preview_columns].head(5).to_string(index=False))


def main() -> int:
    setup_logging()
    load_env_file()
    args = parse_args()

    api_key = get_env_str("VT_API_KEY", "")
    use_mock_vt = bool(args.use_mock_vt or get_env_bool("USE_MOCK_VT", False))

    if not api_key and not use_mock_vt:
        logging.error(
            "Ошибка: не найден VT_API_KEY. Добавьте ключ в переменную окружения "
            "или в локальный .env, либо запустите скрипт с флагом --use-mock-vt "
            "для офлайн-демо."
        )
        return 1

    try:
        alerts_df = read_suricata_alerts(args.log_file)
        candidate_df = extract_candidate_ips(alerts_df)
        summary_df = summarize_candidates(candidate_df)

        enriched_df = enrich_with_virustotal(
            summary_df=summary_df,
            api_key=api_key,
            top_ip_count=max(1, args.top_ip_count),
            timeout=max(1, args.request_timeout),
            sleep_seconds=max(0.0, args.sleep_seconds),
            use_mock_vt=use_mock_vt,
            retries=max(0, args.vt_retries),
            retry_delay=max(0.0, args.vt_retry_delay),
        )

        result_df = add_risk_metrics(enriched_df)

        print_summary(result_df)
        simulate_response(result_df)
        save_report(result_df, args.report_file)
        build_chart(result_df, args.chart_file)

        logging.info("\nГотово. Скрипт завершил работу без ошибок.")
        return 0

    except FileNotFoundError as exc:
        logging.error("Ошибка: %s", exc)
        logging.error(
            "Проверь, что файл логов Suricata существует и путь к нему указан правильно."
        )
        return 1

    except ValueError as exc:
        logging.error("Ошибка обработки данных: %s", exc)
        logging.error(
            "Проверь, что JSON-файл корректен и содержит alert-события "
            "с внешними IP-адресами для анализа."
        )
        return 1

    except Exception as exc:
        logging.error("Ошибка выполнения: %s", exc)
        logging.error(
            "Проверь входные данные, настройки переменных окружения "
            "и доступность VirusTotal API."
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())