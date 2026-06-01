FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SERVICE_NAME=python-microservice \
    PORT=8000

RUN useradd -m appuser
WORKDIR /app

COPY pyproject.toml requirements.txt ./
COPY src ./src
RUN python -m pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install -e . --no-deps

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=2s --retries=5 CMD python -c "import http.client; c=http.client.HTTPConnection('127.0.0.1',8000,timeout=2); c.request('GET','/health'); r=c.getresponse(); exit(0 if r.status==200 else 1)" || exit 1

USER appuser
CMD ["python", "-m", "devsecops_agent.app"]
