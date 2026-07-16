FROM easm-base:latest

WORKDIR /app

COPY requirements/tools.txt .
RUN pip install --no-cache-dir -r tools.txt

COPY backend/ .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
