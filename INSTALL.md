# Инструкция по установке LinShi

## Способ 1 — Автоматическая установка (рекомендуется)

```bash
git clone https://github.com/AidarAkhm/LinShie.git
cd LinShie
chmod +x init.sh && ./init.sh
```

Открыть: `https://ВАШ_IP` | Логин: `admin` | Пароль: `admin123`

---

## Способ 2 — Ручная установка

### Шаг 1. Установка Docker
```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker
```

### Шаг 2. Клонирование репозитория
```bash
git clone https://github.com/AidarAkhm/LinShie.git
cd LinShie
```

### Шаг 3. Генерация SSL
```bash
mkdir -p nginx/ssl
openssl req -x509 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
```

### Шаг 4. Запуск
```bash
docker compose build
docker compose up -d
sleep 20  # Ждём инициализации БД
```

### Шаг 5. Проверка
```bash
docker compose ps  # Все должны быть Up
```

---

## Устранение проблем

### Nginx не стартует
```bash
mkdir -p nginx/ssl
openssl req -x509 -newkey rsa:2048 -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
docker compose restart nginx
```

### Неверный пароль
```bash
docker compose exec backend python -c "
import bcrypt
from database import SessionLocal
from models.user import User
db = SessionLocal()
u = db.query(User).filter(User.username == 'admin').first()
u.hashed_password = bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode()
db.commit()
print('OK')
"
docker compose restart backend
```
