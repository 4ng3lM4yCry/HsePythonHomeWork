def sum_distance(start, end):
    # Если первое число больше второго — меняем местами
    if start > end:
        start, end = end, start

    total = 0
    for number in range(start, end + 1):  # end + 1, чтобы включить end
        total += number

    return total


# Пример использования с вводом от пользователя
a = int(input("Введите первое число: "))
b = int(input("Введите второе число: "))

result = sum_distance(a, b)
print("Сумма чисел от", a, "до", b, "включительно =", result)