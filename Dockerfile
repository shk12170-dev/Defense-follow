FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app app
COPY rules rules
COPY scripts scripts
RUN useradd -m appuser && mkdir -p data logs && chown -R appuser /app
USER appuser

EXPOSE 8000
CMD ["python", "scripts/docker_start.py"]
