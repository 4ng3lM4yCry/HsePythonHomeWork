# Автоматизированный мониторинг и реагирование на угрозы

Этот проект выполнен в рамках итогового задания по Python.

## Установка зависимостей

`pip install requests pandas matplotlib`

## API

Windows PowerShell:

`$env:VT_API_KEY="ваш_ключ"`

`python .\main.py`

Linux / macOS:

`export VT_API_KEY="ваш_ключ"`

`python3 main.py`

## Используемые источники данных
- **Источник 1:** логи Suricata (`alerts-only.json`)
- **Источник 2:** **VirusTotal API v3** для проверки репутации IP-адресов

## Что делает `main.py`
1. Загружает JSON-логи Suricata.
2. Извлекает внешние IP-адреса из alert-событий.
3. Агрегирует события по IP-адресам.
4. Проверяет репутацию IP через VirusTotal.
5. Вычисляет итоговый `risk_score`.
6. Имитирует реагирование:
   - `BLOCK` для high-risk IP;
   - `NOTIFY` для medium-risk IP.
7. Сохраняет:
   - `threat_report.csv`
   - `threat_chart.png`

## Структура проекта
```text
.
├── main.py
├── alerts-only.json
├── README.md
├── threat_report.csv         # создаётся после запуска
└── threat_chart.png          # создаётся после запуска


