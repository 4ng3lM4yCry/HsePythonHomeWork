import json

purchases = {}

with open('purchase_log.txt', 'r', encoding='utf-8') as f:
    next(f)  # пропускаем первую строку с заголовком: user_id,category

    for line in f:
        line = line.strip()
        if not line:          # на всякий случай пропускаем пустые строки
            continue

        data = json.loads(line)           # превращаем JSON-строку в словарь
        user_id = data['user_id']
        category = data['category']
        purchases[user_id] = category

# Проверка: выводим первые два элемента словаря
i = 0
for uid, cat in purchases.items():
    print(uid, cat)
    i += 1
    if i == 2:
        break