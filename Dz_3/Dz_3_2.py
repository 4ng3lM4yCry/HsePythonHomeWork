import json
import csv

# 1. Считываем purchase_log.txt целиком в словарь: user_id -> category
purchases = {}

with open('purchase_log.txt', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        data = json.loads(line)
        purchases[data['user_id']] = data['category']

# 2. Построчно читаем visit_log.csv и пишем только визиты с покупками
with open('visit_log.csv', encoding='utf-8') as visits, \
     open('funnel.csv', 'w', encoding='utf-8', newline='') as funnel:

    reader = csv.reader(visits, delimiter=';')
    writer = csv.writer(funnel, delimiter=';')

    # читаем и дописываем заголовок
    header = next(reader)          # ['user_id', 'source']
    header.append('category')      # ['user_id', 'source', 'category']
    writer.writerow(header)

    for row in reader:             # ['user_id', 'source']
        if not row:
            continue

        user_id = row[0]
        category = purchases.get(user_id)

        if category is not None:
            writer.writerow(row + [category])