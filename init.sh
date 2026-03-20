#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════╗"
echo "║      LinShi — Linux Shield v1.0             ║"
echo "║      Security Audit Platform                 ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Docker ──────────────────────────────────────
if ! command -v docker &>/dev/null; then
  echo -e "${YELLOW}[+] Docker не найден. Устанавливаем...${NC}"
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker $USER
  echo -e "${GREEN}[✓] Docker установлен${NC}"
  echo -e "${YELLOW}[!] Выполните: newgrp docker && ./init.sh${NC}"
  exit 0
fi

# ── 2. SSL сертификат ──────────────────────────────
if [ ! -f "nginx/ssl/cert.pem" ]; then
  echo -e "${YELLOW}[+] Генерация SSL сертификата...${NC}"
  mkdir -p nginx/ssl
  openssl req -x509 -newkey rsa:2048 \
    -keyout nginx/ssl/key.pem \
    -out nginx/ssl/cert.pem \
    -days 365 -nodes \
    -subj "/CN=localhost" 2>/dev/null
  echo -e "${GREEN}[✓] SSL сертификат создан${NC}"
else
  echo -e "${GREEN}[✓] SSL сертификат уже существует${NC}"
fi

# ── 3. Сборка и запуск ────────────────────────────
echo -e "${YELLOW}[+] Сборка контейнеров (может занять 3-5 минут)...${NC}"
docker compose build

echo -e "${YELLOW}[+] Запуск сервисов...${NC}"
docker compose up -d

echo -e "${YELLOW}[+] Ожидание инициализации базы данных...${NC}"
sleep 20

# ── 4. Итог ───────────────────────────────────────
IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════╗"
echo "║         LinShi успешно запущен!              ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  🌐 URL:     https://$IP"
printf "║  👤 Логин:   %-30s ║\n" "admin"
printf "║  🔑 Пароль:  %-30s ║\n" "admin123"
echo "╠══════════════════════════════════════════════╣"
echo "║  ⚠️  Смените пароль после первого входа!     ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"
