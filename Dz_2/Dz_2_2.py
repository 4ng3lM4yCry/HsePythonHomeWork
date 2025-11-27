def trim_and_repeat(text, offset=0, repetitions=1):
    """
    Обрезает строку text слева на offset символов
    и повторяет получившуюся строку repetitions раз.
    """
    trimmed = text[offset:]      # срез строки слева
    result = trimmed * repetitions   # повторение строки
    return result


text = input("Введите строку: ")

# offset с возможным значением по умолчанию (0)
offset_str = input("Сколько символов обрезать слева (offset, Enter = 0): ")
if offset_str == "":
    offset = 0
else:
    offset = int(offset_str)

# repetitions с возможным значением по умолчанию (1)
repetitions_str = input("Сколько раз повторить строку (repetitions, Enter = 1): ")
if repetitions_str == "":
    repetitions = 1
else:
    repetitions = int(repetitions_str)

result = trim_and_repeat(text, offset, repetitions)
print("Результат:", result)