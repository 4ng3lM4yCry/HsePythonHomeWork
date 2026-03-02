"""
Задать API-ключ VirusTotal:
   Linux/macOS:
     export VT_API_KEY="ВАШ_КЛЮЧ"
   Windows (PowerShell):
     $env:VT_API_KEY="ВАШ_КЛЮЧ"
   Windows (CMD):
     set VT_API_KEY=ВАШ_КЛЮЧ

Запуск:
  python vt_client.py 44d88612fea8a8f36de82e1278abb02f
  python vt_client.py https://example.com --raw
  python vt_client.py 8.8.8.8
  python vt_client.py google.com
  python vt_client.py --type file --id <hash> --out out.json
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

import requests

VT_BASE = "https://www.virustotal.com/api/v3"


HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")


def url_to_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def is_valid_ipv4(ip: str) -> bool:
    if not IP_RE.fullmatch(ip):
        return False
    parts = ip.split(".")
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def detect_indicator(value: str) -> Tuple[str, str]:
    v = value.strip()
    if HASH_RE.fullmatch(v):
        return "file", v.lower()
    if is_valid_ipv4(v):
        return "ip", v
    if SCHEME_RE.match(v) or "/" in v:
        return "url", v
    return "domain", v.lower()


def vt_get(session: requests.Session, api_key: str, endpoint: str) -> Dict[str, Any]:
    url = f"{VT_BASE}{endpoint}"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    r = session.get(url, headers=headers, timeout=30)

    # Удобное сообщение об ошибке в формате VT (обычно JSON)
    if r.status_code != 200:
        msg = f"VirusTotal API вернул {r.status_code}."
        try:
            err = r.json()
            msg += f" Ответ: {json.dumps(err, ensure_ascii=False)}"
        except Exception:
            msg += f" Ответ: {r.text}"
        raise RuntimeError(msg)

    return r.json()


def ts_to_iso(ts: Any) -> str | None:
    if ts is None:
        return None
    try:
        ts_int = int(ts)
        return dt.datetime.utcfromtimestamp(ts_int).isoformat() + "Z"
    except Exception:
        return None


def print_stats(stats: Dict[str, Any]) -> None:
    keys = ["malicious", "suspicious", "harmless", "undetected", "timeout"]
    for k in keys:
        if k in stats:
            print(f"  {k}: {stats.get(k)}")
    other = {k: v for k, v in stats.items() if k not in keys}
    for k, v in other.items():
        print(f"  {k}: {v}")


def summarize(kind: str, resp: Dict[str, Any], original: str) -> None:
    data = resp.get("data", {})
    attrs = data.get("attributes", {}) if isinstance(data, dict) else {}

    print(f"Тип индикатора: {kind}")
    print(f"Ввод: {original}")

    if "reputation" in attrs:
        print(f"Reputation: {attrs.get('reputation')}")
    if "last_analysis_date" in attrs:
        print(f"Last analysis date (UTC): {ts_to_iso(attrs.get('last_analysis_date'))}")

    stats = attrs.get("last_analysis_stats") or {}
    if isinstance(stats, dict) and stats:
        print("Статистика анализа:")
        print_stats(stats)

    if kind == "file":
        for k in ["sha256", "sha1", "md5", "size", "meaningful_name", "type_description"]:
            if k in attrs:
                print(f"{k}: {attrs.get(k)}")
    elif kind == "url":
        if "url" in attrs:
            print(f"url: {attrs.get('url')}")
    elif kind == "domain":
        if "tld" in attrs:
            print(f"tld: {attrs.get('tld')}")
    elif kind == "ip":
        if "as_owner" in attrs:
            print(f"as_owner: {attrs.get('as_owner')}")
        if "country" in attrs:
            print(f"country: {attrs.get('country')}")


def build_endpoint(kind: str, indicator: str) -> str:
    if kind == "file":
        return f"/files/{indicator}"
    if kind == "url":
        return f"/urls/{url_to_id(indicator)}"
    if kind == "domain":
        return f"/domains/{indicator}"
    if kind == "ip":
        return f"/ip_addresses/{indicator}"
    raise ValueError(f"Неизвестный тип: {kind}")


def make_default_outfile(kind: str, indicator: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", indicator)[:60]
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(f"vt_response_{kind}_{safe}_{stamp}.json")


def main() -> int:
    parser = argparse.ArgumentParser(description="VirusTotal API v3 client (ДЗ №13)")
    parser.add_argument("indicator", nargs="?", help="Хэш/URL/домен/IP (если не указано — используйте --type и --id)")
    parser.add_argument("--type", choices=["auto", "file", "url", "domain", "ip"], default="auto", help="Тип индикатора")
    parser.add_argument("--id", dest="explicit_id", help="Индикатор, если не хотите передавать позиционно")
    parser.add_argument("--out", default=None, help="Путь к JSON-файлу результата (по умолчанию создаётся автоматически)")
    parser.add_argument("--raw", action="store_true", help="Печатать полный JSON в консоль")
    args = parser.parse_args()

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("Ошибка: переменная окружения VT_API_KEY не задана.", file=sys.stderr)
        return 2

    indicator = args.explicit_id or args.indicator
    if not indicator:
        parser.print_help()
        return 2

    if args.type == "auto":
        kind, norm = detect_indicator(indicator)
    else:
        kind, norm = args.type, indicator.strip()

    endpoint = build_endpoint(kind, norm)

    with requests.Session() as session:
        resp = vt_get(session, api_key, endpoint)

    summarize(kind, resp, indicator)

    out_path = Path(args.out) if args.out else make_default_outfile(kind, norm)
    out_path.write_text(json.dumps(resp, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nJSON сохранён: {out_path.resolve()}")

    if args.raw:
        print("\n--- RAW JSON ---")
        print(json.dumps(resp, ensure_ascii=False, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
