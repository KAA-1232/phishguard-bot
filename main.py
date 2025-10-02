import logging
import os
import hashlib
import secrets
from datetime import datetime, timedelta
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from cryptography.fernet import Fernet
import sqlite3
import json
import re
from functools import wraps
import asyncio

# 🔐 КОНФИГУРАЦИЯ ДЛЯ GITHUB ACTIONS
class PhishGuardConfig:
    # Используем переменные окружения GitHub Actions
    BOT_TOKEN = os.environ.get('BOT_TOKEN', '8495458250:AAHlq0jfbZ7iOTdLjr964AnMTbFndMRgK_w')
    ADMIN_CHAT_ID = os.environ.get('ADMIN_CHAT_ID', '')
    
    # Ключи шифрования
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'github_actions_phishguard_key_2024')
    JWT_SECRET = os.environ.get('JWT_SECRET', 'github_actions_jwt_secret')

    # Лимиты для защиты от спама
    RATE_LIMITS = {
        'messages_per_minute': 10,
        'commands_per_hour': 40,
        'phone_checks_per_day': 20
    }


class SecureDatabase:
    def __init__(self):
        self.fernet = Fernet(PhishGuardConfig.ENCRYPTION_KEY.encode())
        self.init_db()

    def init_db(self):
        """Инициализация защищенной базы данных"""
        with sqlite3.connect('phishguard.db') as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS security_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    threat_level TEXT DEFAULT 'low',
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS rate_limits (
                    user_id TEXT PRIMARY KEY,
                    message_count INTEGER DEFAULT 0,
                    command_count INTEGER DEFAULT 0,
                    last_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS blocked_users (
                    user_id TEXT PRIMARY KEY,
                    reason TEXT,
                    blocked_until TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

    def log_security_event(self, user_id: str, action: str, threat_level: str = 'low', details: str = None):
        """Логирование событий безопасности"""
        with sqlite3.connect('phishguard.db') as conn:
            conn.execute('''
                INSERT INTO security_logs (user_id, action, threat_level, details)
                VALUES (?, ?, ?, ?)
            ''', (user_id, action, threat_level, details))


class PhishGuardBot:
    def __init__(self):
        self.db = SecureDatabase()

        # Базы данных для проверки безопасности
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'clck.ru', 'raboninco.com', 'shorturl.at',
            'cutt.ly', 'is.gd', 'soo.gd', 'sh.st', 'bc.vc', 'adf.ly'
        ]

        self.scam_keywords = [
            'код подтверждения', 'верификация', 'безопасность', 'взлом',
            'перейдите по ссылке', 'срочно', 'немедленно', 'аккаунт заблокирован',
            'техподдержка', 'администратор', 'проверка безопасности',
            'подтвердите личность', 'восстановление доступа', 'системное уведомление'
        ]

        self.bank_phones = {
            '900': 'Сбербанк', '555': 'Тинькофф', '980': 'ЮMoney',
            '962': 'Банк ВТБ', '495': 'Альфа-Банк', '800': 'Единый колл-центр'
        }

        self.operator_codes = {
            '79': 'МегаФон', '89': 'МегаФон', '90': 'Билайн', '93': 'Билайн',
            '91': 'МТС', '98': 'МТС', '92': 'Теле2', '95': 'Теле2',
            '96': 'Yota', '97': 'Yota', '99': 'Билайн'
        }

    async def analyze_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Анализ сообщений на угрозы"""
        try:
            user = update.effective_user
            message = update.message

            if not message.text:
                return

            text = message.text
            user_id = str(user.id)

            # Проверяем, не заблокирован ли пользователь
            if await self._is_user_blocked(user_id):
                await message.reply_text("🚫 Ваш доступ временно ограничен.")
                return

            # Проверка лимитов запросов
            if not await self._check_rate_limit(user_id, 'message'):
                await message.reply_text("⚠️ Слишком много запросов. Подождите.")
                return

            # Анализ угроз
            threats = await self._detect_threats(text, user)

            if threats:
                await self._handle_threats(update, threats, text)
                self.db.log_security_event(user_id, "threat_detected", "high", f"Threats: {threats}")
            else:
                # Логируем чистые сообщения для статистики
                self.db.log_security_event(user_id, "message_checked", "low")

        except Exception as e:
            logging.error(f"PhishGuard error: {e}")
            await self._notify_admin(f"🚨 Ошибка в боте: {str(e)}")

    async def _detect_threats(self, text: str, user) -> list:
        """Обнаружение угроз в сообщении"""
        threats = []
        text_lower = text.lower()

        # 🔗 Проверка подозрительных ссылок
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, text_lower)

        for url in urls:
            if any(domain in url for domain in self.suspicious_domains):
                threats.append(f"Сокращенная ссылка: {url[:50]}")

        # 📞 Проверка номеров телефонов
        phone_pattern = r'[\+\(]?[1-9][0-9\-\(\)\.]{7,}[0-9]'
        phones = re.findall(phone_pattern, text)

        for phone in phones:
            clean_phone = re.sub(r'[^\d]', '', phone)
            # Проверка на банковские номера (часто используются мошенниками)
            for prefix in self.bank_phones.keys():
                if clean_phone.startswith(prefix):
                    threats.append(f"Банковский номер: {phone}")
                    break

        # 💬 Проверка ключевых слов мошенников
        for keyword in self.scam_keywords:
            if keyword in text_lower:
                threats.append(f"Ключевое слово мошенников: '{keyword}'")

        # ⚡ Проверка срочности (социальная инженерия)
        urgency_words = ['срочно', 'немедленно', 'быстрее', 'последний шанс', 'скорее']
        urgency_count = sum(1 for word in urgency_words if word in text_lower)
        if urgency_count >= 2:
            threats.append("Искусственная срочность")

        return threats

    async def _handle_threats(self, update: Update, threats: list, original_text: str):
        """Обработка обнаруженных угроз"""
        user = update.effective_user
        message = update.message

        threat_msg = "🚨 PHISHGUARD ОБНАРУЖИЛ УГРОЗЫ:\n\n"

        for i, threat in enumerate(threats[:5], 1):
            threat_msg += f"{i}. {threat}\n"

        threat_msg += f"\n👤 Отправитель: {user.first_name}"
        if user.username:
            threat_msg += f" (@{user.username})"

        threat_msg += f"\n🆔 ID: {user.id}"
        threat_msg += f"\n💬 Сообщение: {original_text[:100]}..."

        threat_msg += "\n\n🛡️ РЕКОМЕНДАЦИИ:\n"
        threat_msg += "• НЕ переходите по ссылкам\n"
        threat_msg += "• НЕ сообщайте коды подтверждения\n"
        threat_msg += "• Проверьте отправителя\n"
        threat_msg += "• Сообщение будет удалено\n"

        # Уведомление администратора
        if PhishGuardConfig.ADMIN_CHAT_ID:
            await self._notify_admin(threat_msg)

        # Удаление опасного сообщения
        try:
            await message.delete()
            await message.chat.send_message(
                f"🛡️ PhishGuard удалил подозрительное сообщение от {user.first_name}\n"
                f"Обнаружено угроз: {len(threats)}"
            )
        except Exception as e:
            logging.error(f"Не удалось удалить сообщение: {e}")

    async def phone_check(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Проверка номера телефона"""
        user_id = str(update.effective_user.id)

        if not await self._check_rate_limit(user_id, 'command'):
            await update.message.reply_text("⚠️ Слишком много запросов. Подождите.")
            return

        if not context.args:
            await update.message.reply_text(
                "📞 Проверка номера телефона\n\n"
                "Использование: /phone +79123456789\n"
                "Пример: /phone 89501234567"
            )
            return

        phone = context.args[0]
        analysis = self._analyze_phone_number(phone)

        await update.message.reply_text(analysis, parse_mode='HTML')
        self.db.log_security_event(user_id, "phone_check", "low", f"Phone: {phone}")

    def _analyze_phone_number(self, phone: str) -> str:
        """Анализ номера телефона"""
        clean_phone = re.sub(r'[^\d+]', '', phone)

        result = "📊 <b>АНАЛИЗ НОМЕРА:</b>\n\n"
        result += f"🔢 Номер: <code>{phone}</code>\n\n"

        # Определение оператора
        operator = self._identify_operator(clean_phone)
        result += f"📱 Оператор: {operator}\n"

        # Определение банка
        bank = self._identify_bank(clean_phone)
        result += f"🏦 Банк: {bank}\n"

        # Определение региона (для российских номеров)
        if clean_phone.startswith('7') and len(clean_phone) == 11:
            region = self._identify_region(clean_phone[1:4])
            result += f"🌍 Регион: {region}\n"

        result += "\n🛡️ <b>РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ:</b>\n"
        result += "• Проверяйте личность через видеозвонок\n"
        result += "• Не переходите по ссылкам от незнакомцев\n"
        result += "• Никогда не сообщайте коды из SMS\n"
        result += "• Используйте двухфакторную аутентикацию\n"

        result += "\n🔍 <b>ПРОВЕРКА ЧЕРЕЗ БАНКИ:</b>\n"
        result += self._get_bank_check_info(clean_phone)

        return result

    def _identify_operator(self, phone: str) -> str:
        """Определение оператора связи"""
        if phone.startswith('+7'):
            prefix = phone[2:4]
        elif phone.startswith('7'):
            prefix = phone[1:3]
        elif phone.startswith('8'):
            prefix = phone[1:3]
        else:
            prefix = phone[:2]

        return self.operator_codes.get(prefix, "Неизвестный оператор")

    def _identify_bank(self, phone: str) -> str:
        """Определение банка по номеру"""
        clean_phone = re.sub(r'[^\d]', '', phone)
        for prefix, bank in self.bank_phones.items():
            if clean_phone.startswith(prefix) or clean_phone.endswith(prefix):
                return bank
        return "Не определен"

    def _identify_region(self, code: str) -> str:
        """Определение региона"""
        regions = {
            '495': 'Москва', '499': 'Москва', '498': 'Москва',
            '812': 'Санкт-Петербург', '813': 'Ленинградская область',
            '381': 'Омская область', '383': 'Новосибирская область',
            '343': 'Екатеринбург', '846': 'Самара', '863': 'Ростов-на-Дону'
        }
        return regions.get(code, "Регион не определен")

    def _get_bank_check_info(self, phone: str) -> str:
        """Информация для проверки через банки"""
        info = ""
        if phone.startswith('79'):
            info += "• Сбербанк Онлайн: проверка в приложении\n"
        if len(phone) == 11:
            info += "• Тинькофф: перевод по номеру телефона\n"
            info += "• ВТБ: проверка через 'Переводы'\n"
            info += "• Альфа-Банк: проверка в приложении\n"
        return info if info else "• Используйте официальные приложения банков"

    async def security_info(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Информация о безопасности"""
        info_text = """
🛡️ <b>PHISHGUARD BOT - ЗАЩИТА ОТ МОШЕННИКОВ</b>

<b>Автоматические проверки:</b>
• 🔗 Подозрительные ссылки
• 📞 Номера телефонов  
• 💬 Ключевые слова мошенников
• ⚡ Сообщения с искусственной срочностью

<b>Команды:</b>
/start - Запуск бота
/phone +79123456789 - Проверка номера
/security - Эта справка
/stats - Статистика (только для админа)

<b>Что делает бот:</b>
• Автоматически проверяет все сообщения
• Удаляет подозрительные сообщения
• Уведомляет администратора
• Защищает от фишинга и мошенников

<b>Рекомендации:</b>
• Никогда не переходите по подозрительным ссылкам
• Не сообщайте коды из SMS
• Проверяйте незнакомые номера через /phone
• Включите двухфакторную аутентификацию в Telegram
        """
        await update.message.reply_text(info_text, parse_mode='HTML')

    async def admin_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Статистика безопасности (только для админа)"""
        user_id = str(update.effective_user.id)

        if user_id != PhishGuardConfig.ADMIN_CHAT_ID:
            await update.message.reply_text("❌ Доступ только для администратора")
            return

        with sqlite3.connect('phishguard.db') as conn:
            # Статистика угроз
            threat_stats = conn.execute('''
                SELECT threat_level, COUNT(*) FROM security_logs 
                WHERE created_at > datetime('now', '-1 day')
                GROUP BY threat_level
            ''').fetchall()

            # Общая статистика
            total_checks = conn.execute(
                'SELECT COUNT(*) FROM security_logs WHERE created_at > datetime("now", "-1 day")'
            ).fetchone()[0]

            blocked_users = conn.execute(
                'SELECT COUNT(*) FROM blocked_users WHERE blocked_until > CURRENT_TIMESTAMP'
            ).fetchone()[0]

        stats_msg = "📊 <b>СТАТИСТИКА PHISHGUARD</b>\n\n"
        stats_msg += f"🕐 Период: последние 24 часа\n"
        stats_msg += f"🔍 Всего проверок: {total_checks}\n"
        stats_msg += f"🚫 Заблокировано: {blocked_users}\n\n"

        for level, count in threat_stats:
            icon = "🔴" if level == 'high' else "🟡" if level == 'medium' else "🟢"
            stats_msg += f"{icon} Угроз уровня {level}: {count}\n"

        await update.message.reply_text(stats_msg, parse_mode='HTML')

    async def _is_user_blocked(self, user_id: str) -> bool:
        """Проверка блокировки пользователя"""
        with sqlite3.connect('phishguard.db') as conn:
            blocked = conn.execute(
                'SELECT 1 FROM blocked_users WHERE user_id = ? AND (blocked_until > CURRENT_TIMESTAMP OR blocked_until IS NULL)',
                (user_id,)
            ).fetchone()
            return bool(blocked)

    async def _check_rate_limit(self, user_id: str, request_type: str) -> bool:
        """Проверка лимитов запросов"""
        with sqlite3.connect('phishguard.db') as conn:
            user_data = conn.execute(
                'SELECT * FROM rate_limits WHERE user_id = ?', (user_id,)
            ).fetchone()

            now = datetime.now()
            limits = PhishGuardConfig.RATE_LIMITS

            if not user_data:
                conn.execute(
                    'INSERT INTO rate_limits (user_id, message_count, command_count, last_reset) VALUES (?, 1, 0, ?)',
                    (user_id, now)
                )
                return True

            # Сброс счетчиков каждый час
            last_reset = datetime.fromisoformat(user_data[3])
            if now - last_reset > timedelta(hours=1):
                conn.execute(
                    'UPDATE rate_limits SET message_count = 0, command_count = 0, last_reset = ? WHERE user_id = ?',
                    (now, user_id)
                )
                return True

            if request_type == 'message':
                if user_data[1] >= limits['messages_per_minute']:
                    return False
                conn.execute(
                    'UPDATE rate_limits SET message_count = message_count + 1 WHERE user_id = ?',
                    (user_id,)
                )
            elif request_type == 'command':
                if user_data[2] >= limits['commands_per_hour']:
                    return False
                conn.execute(
                    'UPDATE rate_limits SET command_count = command_count + 1 WHERE user_id = ?',
                    (user_id,)
                )

            return True

    async def _notify_admin(self, message: str):
        """Уведомление администратора"""
        if not PhishGuardConfig.ADMIN_CHAT_ID:
            return

        try:
            app = Application.builder().token(PhishGuardConfig.BOT_TOKEN).build()
            await app.bot.send_message(
                chat_id=PhishGuardConfig.ADMIN_CHAT_ID,
                text=message
            )
        except Exception as e:
            logging.error(f"Ошибка уведомления админа: {e}")


# 🚀 ЗАПУСК БОТА ДЛЯ GITHUB ACTIONS
async def main_async():
    """Асинхронная функция запуска для GitHub Actions"""
    try:
        # Проверка токена
        if not PhishGuardConfig.BOT_TOKEN:
            logging.error("❌ BOT_TOKEN не установлен!")
            return

        # Настройка логирования
        logging.basicConfig(
            format='%(asctime)s - PHISHGUARD - %(levelname)s - %(message)s',
            level=logging.INFO
        )

        logging.info("🛡️ Запуск PhishGuard Bot в GitHub Actions...")
        logging.info(f"🤖 Бот: t.me/phishguard_bot")

        if PhishGuardConfig.ADMIN_CHAT_ID:
            logging.info(f"👑 Админ: {PhishGuardConfig.ADMIN_CHAT_ID}")
        else:
            logging.warning("⚠️ ID администратора не установлен")

        # Создание приложения
        application = Application.builder().token(PhishGuardConfig.BOT_TOKEN).build()
        bot = PhishGuardBot()

        # Регистрация обработчиков
        application.add_handler(CommandHandler("start", bot.security_info))
        application.add_handler(CommandHandler("phone", bot.phone_check))
        application.add_handler(CommandHandler("security", bot.security_info))
        application.add_handler(CommandHandler("stats", bot.admin_stats))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.analyze_message))

        # Запуск бота
        logging.info("✅ Бот успешно запущен в GitHub Actions")
        await application.run_polling(drop_pending_updates=True)
        
    except Exception as e:
        logging.error(f"❌ Ошибка: {e}")
        # Ждем перед завершением
        await asyncio.sleep(10)
        raise e

def main():
    """Основная функция запуска"""
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
