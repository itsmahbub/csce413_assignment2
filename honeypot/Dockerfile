FROM python:3.11-slim

WORKDIR /app

COPY honeypot.py .

# Install dependency
RUN pip install --no-cache-dir paramiko

# Create logs directory
RUN mkdir -p /app/logs

# Run as root (needed for port 22)
USER root

EXPOSE 22

CMD ["python", "-u", "honeypot.py"]
