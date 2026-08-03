FROM python:3.12-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    curl \
    openssl \
    git \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# ── External recon binaries (pre-built Go releases) ───────────────────
# Subfinder v2.14.0 — passive subdomain discovery
RUN curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v2.14.0/subfinder_2.14.0_linux_amd64.zip \
    -o /tmp/sf.zip \
    && unzip -o /tmp/sf.zip -d /usr/local/bin/ subfinder \
    && rm /tmp/sf.zip \
    && chmod +x /usr/local/bin/subfinder

# OWASP Amass v4.2.0 — passive + active subdomain enumeration
# oam_subs is bundled inside amass since v4.x (symlink)
# The release zip nests the binary under amass_Linux_amd64/amass rather
# than at the archive root, so extract to a scratch dir first and move
# just the binary into place.
RUN curl -sL https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip \
    -o /tmp/am.zip \
    && unzip -o /tmp/am.zip -d /tmp/am_extract \
    && mv /tmp/am_extract/amass_Linux_amd64/amass /usr/local/bin/amass \
    && rm -rf /tmp/am.zip /tmp/am_extract \
    && chmod +x /usr/local/bin/amass \
    && ln -sf /usr/local/bin/amass /usr/local/bin/oam_subs

# Httpx v1.6.9 — HTTP/HTTPS liveness probe
RUN curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip \
    -o /tmp/hx.zip \
    && unzip -o /tmp/hx.zip -d /usr/local/bin/ httpx \
    && rm /tmp/hx.zip \
    && chmod +x /usr/local/bin/httpx

COPY requirements/base.txt .
RUN pip install --no-cache-dir -r base.txt
