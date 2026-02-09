FROM python:3.11-slim

WORKDIR /app

# Create logs directory
RUN mkdir -p /app/logs


RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       iptables iproute2 netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*


COPY knock_server.py knock_client.py ./


CMD ["sh", "-c", "nc -lvp 2222 & python3 knock_server.py --protected-port 2222 --sequence 1234,5678,9012"]
