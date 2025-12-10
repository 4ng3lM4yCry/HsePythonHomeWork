from datetime import datetime, timedelta

def date_range(start_date: str, end_date: str) -> list[str]:
    """
    Возвращает список дат в формате 'YYYY-MM-DD'
    от start_date до end_date включительно.
    В случае ошибки формата или если start_date > end_date
    возвращается пустой список.
    """
    date_format = '%Y-%m-%d'

    try:
        start = datetime.strptime(start_date, date_format)
        end = datetime.strptime(end_date, date_format)
    except ValueError:
        # Неверный формат или несуществующая дата
        return []

    if start > end:
        return []

    result = []
    current = start

    while current <= end:
        result.append(current.strftime(date_format))
        current += timedelta(days=1)

    return result


if __name__ == '__main__':
    # Запрашиваем даты у пользователя
    start_input = input('Введите дату начала в формате ГГГГ-ММ-ДД: ')
    end_input = input('Введите дату конца в формате ГГГГ-ММ-ДД: ')

    dates = date_range(start_input, end_input)
    print(dates)
