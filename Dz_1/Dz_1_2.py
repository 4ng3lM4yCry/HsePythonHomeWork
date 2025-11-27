boys = ['Peter', 'Alex', 'John', 'Arthur', 'Richard']
girls = ['Kate', 'Liza', 'Kira', 'Emma', 'Trisha']


if len(boys) != len(girls): # проверяем, совпадает ли количество
    print("Внимание, кто-то может остаться без пары!")
else: # Сортируем списки по алфавиту
    boys_sorted = sorted(boys)
    girls_sorted = sorted(girls)

    print("Идеальные пары:")
    for boy, girl in zip(boys_sorted, girls_sorted): #берём элементы с одинаковыми индексами из двух списков
        print(f"{boy} и {girl}")