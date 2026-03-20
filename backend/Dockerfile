FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    nmap \
    net-tools \
    openssh-client \
    iproute2 \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN alembic upgrade head 2>/dev/null || true

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
