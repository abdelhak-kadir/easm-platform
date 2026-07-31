FROM python:3.12-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    curl \
    openssl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/base.txt .
RUN pip install --no-cache-dir -r base.txt
