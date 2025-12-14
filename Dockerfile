# -----------------------------
# Base image
# -----------------------------
FROM python:3.11-slim

# -----------------------------
# Environment settings
# -----------------------------
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# -----------------------------
# Install system dependencies
# -----------------------------
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    unzip \
    ca-certificates \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------
# Install security tools
# -----------------------------

# Subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.6.6_linux_amd64.zip \
    && unzip subfinder_2.6.6_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.6_linux_amd64.zip

# Httpx
RUN wget -q https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_1.6.7_linux_amd64.zip \
    && unzip httpx_1.6.7_linux_amd64.zip \
    && mv httpx /usr/local/bin/ \
    && rm httpx_1.6.7_linux_amd64.zip

# Naabu
RUN wget -q https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_2.3.4_linux_amd64.zip \
    && unzip naabu_2.3.4_linux_amd64.zip \
    && mv naabu /usr/local/bin/ \
    && rm naabu_2.3.4_linux_amd64.zip

# Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.2.4_linux_amd64.zip \
    && unzip nuclei_3.2.4_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.2.4_linux_amd64.zip

# -----------------------------
# Set working directory
# -----------------------------
WORKDIR /app

# -----------------------------
# Copy project files
# -----------------------------
COPY . /app

# -----------------------------
# Install Python dependencies
# -----------------------------
RUN pip install --no-cache-dir -r requirements.txt

# -----------------------------
# Expose Flask port
# -----------------------------
EXPOSE 5000

# -----------------------------
# Run the application
# -----------------------------
CMD ["python", "app.py"]
