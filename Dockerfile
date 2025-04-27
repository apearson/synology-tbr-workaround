FROM python:3.9-slim

# Install required system packages
RUN apt-get update && apt-get install -y \
    iproute2 \
    libpcap-dev

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY rio_handler.py .

# Run with network capabilities needed for IPv6 and packet capture
CMD ["python", "-u", "./rio_handler.py"]