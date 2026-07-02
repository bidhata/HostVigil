FROM python:3.11-slim

LABEL maintainer="Krishnendu Paul <me@krishnendu.com>"
LABEL description="HostVigil - Stealth Internal Recon Platform"

WORKDIR /app

# Install system deps for scapy (optional raw packet support)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directories
RUN mkdir -p data/logs data/models data/scans data/reports data/pcap plugins

# Expose dashboard port
EXPOSE 5000

# Default: run daemon (scanner + dashboard)
ENTRYPOINT ["python", "run.py"]
CMD ["daemon"]
