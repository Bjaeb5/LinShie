<div align="center">

# 🛡️ LinShi — Linux Shield

### Платформа аудита безопасности Linux-серверов

[![Version](https://img.shields.io/badge/version-1.0.0-blue?style=flat-square)](https://github.com/AidarAkhm/LinShie)
[![Python](https://img.shields.io/badge/python-3.11-3776ab?style=flat-square&logo=python)](https://python.org)
[![React](https://img.shields.io/badge/react-18-61dafb?style=flat-square&logo=react)](https://react.dev)
[![Docker](https://img.shields.io/badge/docker-compose-2496ed?style=flat-square&logo=docker)](https://docker.com)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![CIS](https://img.shields.io/badge/standard-CIS%20Benchmarks-red?style=flat-square)](https://www.cisecurity.org)
[![NIST](https://img.shields.io/badge/standard-NIST%20SP%20800--53-orange?style=flat-square)](https://csrc.nist.gov)

**LinShi** — интеллектуальная система мониторинга и аудита безопасности Linux-серверов.  
Анализирует конфигурацию, обнаруживает уязвимости и выдаёт рекомендации по стандартам CIS, NIST и OWASP.

[🚀 Быстрый старт](#-быстрый-старт) · [✨ Возможности](#-возможности) · [📖 Документация](#️-архитектура) · [👤 Автор](#-автор)

</div>

---

## 🚀 Быстрый старт

### Требования
| | Минимум | Рекомендуется |
|---|---|---|
| OS | Ubuntu 20.04 / Debian 11 | Ubuntu 22.04 LTS |
| RAM | 2 GB | 4 GB |
| Диск | 10 GB | 20 GB |
| Порты | 80, 443 | 80, 443 |

### Установка одной командой

```bash
git clone https://github.com/AidarAkhm/LinShie.git
cd LinShie
chmod +x init.sh && ./init.sh
```

Скрипт автоматически:
- ✅ Установит Docker (если не установлен)
- ✅ Сгенерирует SSL-сертификат
- ✅ Соберёт все контейнеры
- ✅ Создаст admin-пользователя

### Доступ к системе

```
🌐 Откройте: https://ВАШ_IP

Логин:  admin
Пароль: admin123
```

> ⚠️ Смените пароль после первого входа в разделе **Пользователи**

---

## ✨ Возможности

### 📊 Дашборд безопасности
- Индекс безопасности сервера (0–100)
- Графики: радиальный индикатор, круговые диаграммы, бар-чарты
- Прогресс соответствия стандартам CIS / NIST / OWASP
- История последних сканирований

### 🔍 Сканирование (24+ проверки)

| Категория | Проверки |
|-----------|----------|
| **SSH** | root-логин, парольная аутентификация, версия протокола, максимум попыток, пустые пароли, шифры, MAC |
| **Пароли** | минимальная длина, срок действия, сложность (pam_pwquality), пустые пароли |
| **Сеть** | UFW, IP forwarding, TCP SYN cookies, опасные открытые порты |
| **Система** | обновления ОС, SUID-файлы, auditd, fail2ban, автообновления, cron, ядро, AppArmor, /tmp noexec |

Каждая проверка маппируется на стандарты CIS Benchmarks и NIST SP 800-53.

### 🖥️ Удалённые хосты
- Добавление серверов по IP/hostname
- Сканирование по SSH (пароль или ключ)
- Каталог с историей проверок

### 📋 Групповые политики
GPO-аналог для Linux-серверов. Шаблоны политик:
- **SSH-безопасность** — отключение root, требование ключей
- **Политика паролей** — длина, сложность, срок действия
- **Фаервол** — базовые правила UFW
- **Аудит** — включение auditd
- **Автообновления** — unattended-upgrades

Применение на один или несколько хостов одновременно.

### 🛡️ Инструменты защиты
Каталог из 8 программ с описанием, перечнем предотвращаемых атак и готовыми командами установки:

| Инструмент | Категория | Защищает от |
|-----------|-----------|-------------|
| **Fail2Ban** | Защита от брутфорса | SSH/RDP brute force, HTTP атаки |
| **UFW** | Фаервол | Сканирование портов, DDoS, Lateral Movement |
| **auditd** | Аудит | Privilege Escalation, утечка данных |
| **AppArmor** | MAC | Container Escape, эксплуатация ПО |
| **ClamAV** | Антивирус | Трояны, веб-шеллы, вредоносные файлы |
| **OSSEC/Wazuh** | HIDS | Rootkit, изменение системных файлов |
| **rkhunter** | Антируткит | Rootkit, backdoor, скрытые процессы |
| **Lynis** | Аудит | Неправильная конфигурация, несоответствие стандартам |

### ⚡ Анализ киберугроз
8 типов современных атак с подробным разбором:

| Атака | Серьёзность | Признаки | Меры защиты |
|-------|-------------|----------|-------------|
| Брутфорс SSH/RDP | 🔴 Критическая | Логи auth.log | Fail2Ban, ключи SSH |
| DDoS / SYN Flood | 🟠 Высокая | Аномальный трафик | SYN cookies, UFW |
| Privilege Escalation | 🔴 Критическая | SUID файлы | AppArmor, обновления |
| Ransomware | 🔴 Критическая | Зашифрованные файлы | Бэкапы, AppArmor |
| MITM | 🟠 Высокая | SSL-предупреждения | TLS 1.3, HSTS |
| Web Shell / RCE | 🔴 Критическая | Подозрительные файлы | AppArmor, auditd |
| Supply Chain | 🟠 Высокая | Изменения пакетов | GPG проверка |
| Lateral Movement | 🟠 Высокая | Необычные SSH | Сегментация сети |

### 🎯 Тестирование защиты

**Симуляция атак** — читает реальную конфигурацию сервера и определяет уязвимость к 8 типам атак без реального воздействия.

**Pentest Checklist** — 15 проверок по 5 фазам с готовыми командами:
1. Разведка (Reconnaissance)
2. Анализ аутентификации
3. Проверка сети и фаервола
4. Повышение привилегий
5. Аудит логов и обнаружение

### 👥 Управление пользователями
- Роли: **Администратор**, **Оператор**, **Наблюдатель**
- JWT аутентификация (access + refresh токены)
- bcrypt хэширование паролей

### 🌐 Мультиязычность
Переключение RU / EN в сайдбаре. Выбор сохраняется между сессиями.

---

## 🏗️ Архитектура

```
┌─────────────────────────────────────────────────────┐
│              Nginx (SSL/TLS)  :80 :443               │
└──────────────────┬──────────────────────────────────┘
                   │
        ┌──────────┴───────────┐
        │                      │
┌───────▼────────┐    ┌────────▼────────┐
│   Frontend     │    │   Backend API   │
│  React 18 +    │    │  FastAPI +      │
│  TypeScript    │    │  Python 3.11    │
│  Tailwind CSS  │    │  :8000          │
└────────────────┘    └────────┬────────┘
                               │
               ┌───────────────┼──────────────┐
               │               │              │
    ┌──────────▼─┐  ┌──────────▼─┐  ┌────────▼──────┐
    │ PostgreSQL │  │   Redis    │  │    Celery     │
    │    15      │  │     7      │  │   Workers     │
    │  (данные)  │  │  (кэш/кью) │  │  (сканирование│
    └────────────┘  └────────────┘  └───────────────┘
```

### Технологический стек

| Слой | Технологии |
|------|-----------|
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Recharts, React Router |
| **Backend** | FastAPI, Python 3.11, SQLAlchemy 2.0, Alembic |
| **База данных** | PostgreSQL 15 |
| **Кэш / Очереди** | Redis 7 + Celery 5 |
| **Аутентификация** | JWT, bcrypt 4.0 |
| **SSH-сканирование** | paramiko |
| **Прокси** | Nginx с SSL/TLS |
| **Развёртывание** | Docker 24 + Docker Compose v2 |

---

## 📁 Структура проекта

```
LinShie/
├── 📄 docker-compose.yml          # Оркестрация 6 сервисов
├── 📄 .env                        # Переменные окружения
├── 📄 init.sh                     # Скрипт автоустановки
├── 📂 nginx/
│   ├── nginx.conf                 # HTTPS, proxy_pass, security headers
│   └── ssl/                       # SSL сертификаты (генерируются)
├── 📂 backend/
│   ├── Dockerfile
│   ├── requirements.txt           # bcrypt==4.0.1 (без passlib)
│   ├── main.py                    # FastAPI app, startup events
│   ├── database.py                # SQLAlchemy engine, session
│   ├── celery_app.py              # Celery конфигурация
│   ├── tasks.py                   # Асинхронные задачи сканирования
│   ├── 📂 models/
│   │   ├── user.py                # User, роли, is_active
│   │   ├── host.py                # RemoteHost, SSH параметры
│   │   ├── scan.py                # ScanResult, findings JSON
│   │   └── policy.py             # SecurityPolicy, rules
│   ├── 📂 routers/
│   │   ├── auth.py                # /login, /refresh, /me
│   │   ├── scans.py               # /scans, /scans/local
│   │   ├── hosts.py               # CRUD хостов
│   │   ├── users.py               # CRUD пользователей
│   │   └── policies.py            # Политики, применение
│   ├── 📂 services/
│   │   ├── user_service.py        # bcrypt auth, JWT
│   │   ├── remote_scanner.py      # SSH сканирование
│   │   └── policy_engine.py       # Применение политик
│   └── 📂 checks/
│       └── scanner.py             # 24+ проверок CIS/NIST
└── 📂 frontend/
    ├── Dockerfile                 # node:20-alpine + nginx
    ├── package.json
    ├── vite.config.ts
    ├── tailwind.config.js
    └── 📂 src/
        ├── App.tsx                # Роутинг, AuthContext
        ├── i18n.tsx               # Переводы RU/EN
        ├── 📂 api/
        │   └── index.ts           # axios клиент, interceptors
        ├── 📂 components/
        │   └── Layout.tsx         # Сайдбар, навигация, переключатель языка
        └── 📂 pages/
            ├── Login.tsx
            ├── Dashboard.tsx      # Recharts графики, индекс безопасности
            ├── Scans.tsx
            ├── Hosts.tsx
            ├── Policies.tsx
            ├── Tools.tsx          # Каталог 8 инструментов
            ├── CyberAttacks.tsx   # 8 типов атак
            ├── SecurityTesting.tsx # Симуляция + Pentest Checklist
            ├── Users.tsx
            └── About.tsx          # О создателе
```

---

## ⚙️ Конфигурация

### Переменные окружения (.env)

```env
# ── База данных ───────────────────────────────────
POSTGRES_DB=linuxshield
POSTGRES_USER=linuxshield
POSTGRES_PASSWORD=SecureLinShi2024!       # Смените в продакшне
DATABASE_URL=postgresql://linuxshield:SecureLinShi2024!@postgres:5432/linuxshield

# ── Redis ─────────────────────────────────────────
REDIS_URL=redis://redis:6379/0

# ── JWT ───────────────────────────────────────────
SECRET_KEY=linshi-secret-key-change-in-production-256bits
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# ── Администратор (создаётся автоматически) ───────
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ADMIN_EMAIL=admin@company.local
```

### Смена пароля администратора

```bash
docker compose exec backend python -c "
import bcrypt
from database import SessionLocal
from models.user import User
db = SessionLocal()
u = db.query(User).filter(User.username == 'admin').first()
u.hashed_password = bcrypt.hashpw(b'НовыйПароль', bcrypt.gensalt()).decode()
db.commit()
print('Пароль обновлён успешно')
"
docker compose restart backend
```

---

## 🛠️ Управление

### Основные команды

```bash
# Статус всех сервисов
docker compose ps

# Логи в реальном времени
docker compose logs -f backend
docker compose logs -f nginx
docker compose logs -f frontend

# Перезапуск конкретного сервиса
docker compose restart backend
docker compose restart nginx

# Полная остановка
docker compose down

# Полная переустановка (данные сохраняются)
git pull
docker compose build --no-cache
docker compose up -d

# Полный сброс (УДАЛЯЕТ ВСЕ ДАННЫЕ)
docker compose down -v
./init.sh
```

---

## 🔧 Устранение проблем

### ❌ Nginx не запускается — ошибка SSL

```bash
# Генерация сертификата
mkdir -p nginx/ssl
openssl req -x509 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
docker compose restart nginx
```

### ❌ Неверный логин/пароль

```bash
# Сброс пароля администратора
docker compose exec backend python -c "
import bcrypt
from database import SessionLocal
from models.user import User
db = SessionLocal()
u = db.query(User).filter(User.username == 'admin').first()
if not u:
    from models import Base
    from database import engine
    Base.metadata.create_all(bind=engine)
    from services.user_service import hash_password
    u = User(username='admin', email='admin@local.com',
             hashed_password=hash_password('admin123'), role='admin', is_active=True)
    db.add(u)
else:
    u.hashed_password = bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode()
db.commit()
print('OK — логин: admin, пароль: admin123')
"
docker compose restart backend
```

### ❌ Ошибка bcrypt/passlib

Эта версия проекта уже использует `bcrypt==4.0.1` напрямую без `passlib`.  
Если видите `module 'bcrypt' has no attribute '__about__'` — выполните полную переустановку:

```bash
docker compose down -v
docker compose build --no-cache
docker compose up -d
```

### ❌ База данных недоступна

```bash
docker compose logs postgres
docker compose restart postgres
sleep 15
docker compose restart backend celery
```

---

## 🔒 Стандарты безопасности

### CIS Benchmarks v8 — Ubuntu 22.04

| Раздел | Проверки LinShi |
|--------|----------------|
| 1. Начальная настройка | Автообновления, AppArmor |
| 2. Сервисы | Открытые порты, отключение лишних сервисов |
| 3. Сетевая конфигурация | IP Forwarding, SYN cookies, UFW |
| 4. Ведение журналов | auditd, rsyslog |
| 5. Доступ, аутентификация | SSH, sudo, пароли, PAM |
| 6. Обслуживание системы | SUID файлы, права /tmp |

### NIST SP 800-53 Rev. 5

| Семейство | Контроли |
|-----------|---------|
| **AC** — Управление доступом | AC-2, AC-6, AC-7, AC-17 |
| **AU** — Аудит | AU-2, AU-3, AU-9, AU-12 |
| **CM** — Управление конфигурацией | CM-6, CM-7 |
| **IA** — Идентификация и аутентификация | IA-5 |
| **SC** — Защита систем и коммуникаций | SC-5, SC-7, SC-8 |
| **SI** — Целостность систем | SI-2, SI-3 |

---

## 📊 Система оценки

| Индекс | Уровень | Описание |
|--------|---------|----------|
| 80–100 | 🟢 Хорошо | Большинство проверок пройдено |
| 60–79 | 🟡 Средне | Есть важные уязвимости |
| 0–59 | 🔴 Критично | Сервер требует немедленного внимания |

---

## 📄 Лицензия

MIT License — свободное использование с указанием авторства.

---

## 👤 Автор

<div align="center">

### Айдар Ахманов

**Магистрант** Евразийского Национального университета имени Л.Н. Гумилева  
**Специальность:** Системы информационной безопасности

[![Telegram](https://img.shields.io/badge/Telegram-@Bjebs-2ca5e0?style=for-the-badge&logo=telegram)](https://t.me/Bjebs)
[![GitHub](https://img.shields.io/badge/GitHub-AidarAkhm-black?style=for-the-badge&logo=github)](https://github.com/AidarAkhm)

*Проект разработан в рамках магистерской диссертации:*  
*«Исследование комплексных методов защиты физических и виртуальных Linux-серверов в условиях современных киберугроз»*

</div>
