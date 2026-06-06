FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY iptools.py .
COPY app.py .
COPY gunicorn_config.py .
COPY templates/ ./templates/

RUN useradd -r -u 1001 appuser && chown -R appuser /app
USER appuser

EXPOSE 8000
CMD ["gunicorn", "--config", "gunicorn_config.py", "app:app"]
