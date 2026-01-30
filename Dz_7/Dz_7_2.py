import os
import requests


BASE_URL = "https://api.openweathermap.org/data/2.5/weather"


def get_api_key() -> str:
    # 1) предпочтительно: переменная окружения
    key = os.getenv("OPENWEATHER_API_KEY", "").strip()
    if key:
        return key

    # 2) запасной вариант: ввод руками
    return input("Введи OpenWeather API key: ").strip()


def main() -> None:
    api_key = get_api_key()
    if not api_key:
        print("[ERROR] API key пустой.")
        return

    city = input("Введи город: ").strip()
    if not city:
        print("[ERROR] Город пустой.")
        return

    params = {
        "q": city,
        "appid": api_key,
        "units": "metric",  # градусы C
        "lang": "ru",       # описание по-русски
    }

    try:
        resp = requests.get(BASE_URL, params=params, timeout=15)
        # OpenWeather иногда возвращает JSON с ошибкой и 200/404 — поэтому проверим JSON тоже
        data = resp.json()
    except requests.RequestException as e:
        print(f"[ERROR] Ошибка запроса: {e}")
        return
    except ValueError:
        print("[ERROR] Ответ не JSON (или пустой).")
        return

    # Если ошибка (например, город не найден)
    cod = str(data.get("cod", ""))
    if cod != "200":
        msg = data.get("message", "unknown error")
        print(f"[ERROR] OpenWeather вернул ошибку (cod={cod}): {msg}")
        return

    temp = data.get("main", {}).get("temp")
    desc = ""
    weather_list = data.get("weather", [])
    if isinstance(weather_list, list) and weather_list:
        desc = weather_list[0].get("description", "")

    name = data.get("name", city)

    print(f"Город: {name}")
    print(f"Температура: {temp} °C")
    print(f"Погода: {desc}")


if __name__ == "__main__":
    main()