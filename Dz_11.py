import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
from datetime import datetime

# ====================== Загрузка и подготовка данных ======================
# Чтение JSON-файла
with open('botsv1.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Извлечение поля 'result' из каждой записи
results = [item['result'] for item in data]

# Нормализация вложенных структур в DataFrame
df = pd.json_normalize(results)

# Просмотр первых строк
print("Первые 5 записей:")
print(df.head())

# Проверка наличия временной метки '_time' – используем её как единый формат времени
if '_time' in df.columns:
    df['timestamp'] = pd.to_datetime(df['_time'], errors='coerce')
else:
    # Если нет, собираем из отдельных полей (на всякий случай)
    month_map = {
        'january': 1, 'february': 2, 'march': 3, 'april': 4,
        'may': 5, 'june': 6, 'july': 7, 'august': 8,
        'september': 9, 'october': 10, 'november': 11, 'december': 12
    }
    df['month_num'] = df['date_month'].map(month_map)
    df['timestamp'] = pd.to_datetime(
        df['date_year'].astype(str) + '-' + 
        df['month_num'].astype(str) + '-' + 
        df['date_mday'].astype(str) + ' ' +
        df['date_hour'].astype(str) + ':' +
        df['date_minute'].astype(str) + ':' +
        df['date_second'].astype(str),
        errors='coerce'
    )

# Нормализация полей, которые могут быть списками (берём первый элемент или объединяем)
for col in df.columns:
    if df[col].apply(lambda x: isinstance(x, list)).any():
        # Преобразуем список в строку через запятую
        df[col] = df[col].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x)

# ====================== Разделение на два типа логов ======================
# В данных присутствует только WinEventLog, но создадим два датафрейма для полноты
win_logs = df[df['sourcetype'].str.contains('WinEventLog', na=False)].copy()
dns_logs = df[df['sourcetype'].str.contains('DNS', na=False)].copy()

print(f"\nНайдено записей WinEventLog: {len(win_logs)}")
print(f"Найдено записей DNS: {len(dns_logs)}")

# ====================== Анализ WinEventLog ======================
# Список подозрительных EventID (на основе известных индикаторов компрометации)
# Источник: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
suspicious_eventids = [
    4624, 4625, 4648, 4672, 4688, 4703, 4719, 4720, 4732, 4768, 4769,
    4776, 4798, 4799, 4800, 4801, 4802, 4803, 5379, 5382, 4656, 4689
]

# Добавим EventID из наших данных, если их нет в списке (для демонстрации)
present_ids = win_logs['EventCode'].unique()
for eid in present_ids:
    if eid not in suspicious_eventids:
        suspicious_eventids.append(int(eid))

# Фильтруем только подозрительные события
win_suspicious = win_logs[win_logs['EventCode'].astype(int).isin(suspicious_eventids)]

# Подсчёт частоты подозрительных событий
suspicious_counts = win_suspicious['EventCode'].value_counts().reset_index()
suspicious_counts.columns = ['EventCode', 'Count']

# Берём топ-10
top10_suspicious = suspicious_counts.head(10)

print("\nТоп-10 подозрительных событий WinEventLog:")
print(top10_suspicious)

# ====================== Анализ DNS-логов (если бы они были) ======================
if not dns_logs.empty:
    # Здесь можно реализовать логику поиска подозрительных DNS-запросов
    # Например, частые запросы к редким доменам, длинные поддомены и т.д.
    # Для демонстрации просто посчитаем топ-10 доменов
    dns_suspicious = dns_logs['query'].value_counts().head(10).reset_index()
    dns_suspicious.columns = ['Domain', 'Count']
    print("\nТоп-10 DNS-запросов (потенциально подозрительные):")
    print(dns_suspicious)
else:
    print("\nDNS-логи отсутствуют в предоставленном файле.")

# ====================== Визуализация ======================
plt.figure(figsize=(12, 6))
sns.barplot(data=top10_suspicious, x='EventCode', y='Count', palette='viridis')
plt.title('Топ-10 подозрительных событий WinEventLog по EventID')
plt.xlabel('Event ID')
plt.ylabel('Количество')
plt.xticks(rotation=45)
plt.tight_layout()

# Сохранение графика
plt.savefig('top10_suspicious_winevent.png')
plt.show()

# Если есть DNS-логи, можно построить отдельный график
if not dns_logs.empty:
    plt.figure(figsize=(12, 6))
    sns.barplot(data=dns_suspicious, x='Domain', y='Count', palette='magma')
    plt.title('Топ-10 DNS-запросов')
    plt.xlabel('Домен')
    plt.ylabel('Количество')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('top10_dns.png')
    plt.show()

print("\nАнализ завершён. Графики сохранены.")