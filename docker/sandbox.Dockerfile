FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/workspace/src \
    PYTEST_ADDOPTS="-p no:cacheprovider"

RUN apt-get update \
    && apt-get install -y --no-install-recommends make ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/skillchain-deps
COPY pyproject.toml requirements.txt requirements-dev.txt requirements-mcp.txt ./
RUN python -m pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install -r requirements-dev.txt \
    && pip install -r requirements-mcp.txt

WORKDIR /workspace
CMD ["make", "unit"]
