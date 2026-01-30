import requests


URL = "https://jsonplaceholder.typicode.com/posts"


def main() -> None:
    try:
        resp = requests.get(URL, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[ERROR] Не удалось получить данные: {e}")
        return

    try:
        posts = resp.json()
        if not isinstance(posts, list):
            raise ValueError("Ответ не список постов")
    except Exception as e:
        print(f"[ERROR] Не удалось распарсить JSON: {e}")
        return

    for post in posts[:5]:
        title = post.get("title", "")
        body = post.get("body", "")
        post_id = post.get("id", "N/A")

        print(f"Post #{post_id}")
        print(f"Title: {title}")
        print(f"Body: {body}")
        print("-" * 40)


if __name__ == "__main__":
    main()
