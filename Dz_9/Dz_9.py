from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Union, Optional

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


def load_events_json(path: Union[str, Path]) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Файл не найден: {p.resolve()}")

    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "events" in data and isinstance(data["events"], list):
        return data["events"]
    if isinstance(data, list):
        return data

    raise ValueError("Неподдерживаемая структура JSON: ожидаю {'events': [...]} или список [...]")


def prepare_dataframe(events: List[Dict[str, Any]]) -> pd.DataFrame:
    df = pd.DataFrame(events)

    if "signature" not in df.columns:
        raise ValueError("В данных нет поля 'signature' — невозможно построить распределение.")

    df["signature"] = df["signature"].astype("string").fillna("<missing>").str.strip()

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    return df


def compute_signature_counts(df: pd.DataFrame, top: Optional[int]) -> pd.Series:
    counts = df["signature"].value_counts(dropna=False)

    if top is None or top <= 0 or top >= len(counts):
        return counts

    top_counts = counts.head(top)
    other_sum = counts.iloc[top:].sum()
    if other_sum > 0:
        top_counts = pd.concat([top_counts, pd.Series({f"Other ({len(counts) - top})": other_sum})])

    return top_counts


def plot_counts(counts: pd.Series, title: str, out_path: str | None, show: bool) -> None:
    plt.figure(figsize=(12, max(4, 0.45 * len(counts))))
    sns.barplot(x=counts.values, y=counts.index)

    plt.title(title)
    plt.xlabel("Количество событий")
    plt.ylabel("Тип события (signature)")
    plt.tight_layout()

    if out_path:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(out_path, dpi=200)
        print(f"[OK] График сохранён: {Path(out_path).resolve()}")

    if show:
        plt.show()

    plt.close()


def pick_file_cli(search_dir: Path) -> Path:
    json_files = sorted([p for p in search_dir.iterdir() if p.is_file() and p.suffix.lower() == ".json"])

    print(f"\nПоиск .json в папке: {search_dir.resolve()}")
    if json_files:
        for i, p in enumerate(json_files, 1):
            print(f"  {i}) {p.name}")
        print("  0) Ввести путь вручную")

        while True:
            choice = input("\nВыбери номер файла (или Enter чтобы выйти): ").strip()
            if choice == "":
                raise SystemExit("Выход: файл не выбран.")
            if choice.isdigit():
                n = int(choice)
                if n == 0:
                    break
                if 1 <= n <= len(json_files):
                    return json_files[n - 1]
            print("Неверный выбор. Попробуй ещё раз.")
    else:
        print("В этой папке .json файлов не найдено.")

    while True:
        manual = input("Введи путь к .json (или Enter чтобы выйти): ").strip().strip('"')
        if manual == "":
            raise SystemExit("Выход: файл не выбран.")
        p = Path(manual)
        if p.exists() and p.is_file() and p.suffix.lower() == ".json":
            return p
        print("Путь неверный или это не .json файл. Попробуй ещё раз.")


def pick_file_gui(initial_dir: Path) -> Path:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception:
        print("[WARN] tkinter недоступен, переключаюсь на выбор в консоли.")
        return pick_file_cli(initial_dir)

    root = tk.Tk()
    root.withdraw()
    root.update()
    file_path = filedialog.askopenfilename(
        initialdir=str(initial_dir.resolve()),
        title="Выберите JSON файл",
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
    )
    root.destroy()

    if not file_path:
        raise SystemExit("Выход: файл не выбран.")
    return Path(file_path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ДЗ 9: загрузка JSON в DataFrame и визуализация распределения по signature."
    )
    parser.add_argument(
        "-i", "--input",
        default=None,
        help="Путь к JSON-файлу. Если не указан — предложит выбрать из текущей папки."
    )
    parser.add_argument(
        "--dir",
        default=".",
        help="Папка для поиска .json при интерактивном выборе (по умолчанию: текущая)."
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Открыть диалог выбора файла (если доступен tkinter)."
    )
    parser.add_argument(
        "--top",
        type=int,
        default=0,
        help="Показать только TOP-N типов (0 = показать все). Например: 15."
    )
    parser.add_argument(
        "-o", "--out",
        default="signature_distribution.png",
        help="Куда сохранить PNG (по умолчанию: signature_distribution.png)."
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Не сохранять график в файл (только показать)."
    )
    parser.add_argument(
        "--no-show",
        action="store_true",
        help="Не показывать окно с графиком (удобно для терминала/CI)."
    )
    args = parser.parse_args()

    search_dir = Path(args.dir)

    if args.input:
        input_path = Path(args.input)
    else:
        input_path = pick_file_gui(search_dir) if args.gui else pick_file_cli(search_dir)

    events = load_events_json(input_path)
    df = prepare_dataframe(events)

    top = None if args.top <= 0 else args.top
    counts = compute_signature_counts(df, top=top)

    print(f"\nФайл: {input_path.resolve()}")
    print("\nРаспределение событий по signature:")
    print(counts.to_string())

    out_path = None if args.no_save else args.out
    show = not args.no_show

    plot_counts(
        counts=counts,
        title="Распределение типов событий безопасности (signature)",
        out_path=out_path,
        show=show,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())