FROM python:3.11-slim

# Install recon tools
RUN apt update && apt install -y \
    nmap \
    netcat-openbsd \
    curl \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY knock_client.py ./

CMD ["bash"]
