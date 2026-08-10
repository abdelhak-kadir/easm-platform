FROM easm-base:latest

WORKDIR /app

COPY requirements/tools.txt .
RUN pip install --no-cache-dir -r tools.txt

# Re-install Go httpx — the Python httpx library (a dependency of theHarvester)
# installs its own CLI binary at /usr/local/bin/httpx which shadows the
# ProjectDiscovery Go binary. We need the Go version for HTTP probing.
RUN curl -sL --connect-timeout 30 --max-time 300 --retry 3 https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip \
    -o /tmp/hx.zip \
    && unzip -o /tmp/hx.zip -d /usr/local/bin/ httpx \
    && rm /tmp/hx.zip \
    && chmod +x /usr/local/bin/httpx

COPY backend/ .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
