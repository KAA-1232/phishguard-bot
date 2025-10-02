# setup.py - запустите этот файл для настройки бота
import os


def setup_bot():
    print("🛠 Настройка PhishGuard Bot...")

    # Запрос данных у пользователя
    bot_token = input("Введите токен бота (уже есть): 8495458250:AAHlq0jfbZ7iOTdLjr964AnMTbFndMRgK_w\n")
    admin_id = input("Введите ваш ID Telegram (узнать у @userinfobot): ")

    # Создание .env файла
    env_content = f"""CYBER_GUARD_TOKEN={bot_token}
CYBER_GUARD_ADMIN={admin_id}
"""

    with open('.env', 'w', encoding='utf-8') as f:
        f.write(env_content)

    print("✅ Файл .env успешно создан!")
    print("🚀 Теперь запустите: python main.py")


if __name__ == "__main__":
    setup_bot()