ARG PYTHON_IMAGE=python:3.13.14-slim-trixie

FROM ${PYTHON_IMAGE} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY pyproject.toml requirements.txt ./
COPY src ./src

# Las herramientas de construcción permanecen únicamente en builder.
RUN python -m pip install --no-cache-dir \
        "pip==26.2" \
        "setuptools==83.0.0" \
        wheel \
        "build==1.2.2.post1" \
    && python -m build --wheel \
    && python -m pip install \
        --no-cache-dir \
        --no-deps \
        --prefix=/install \
        dist/*.whl


FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SERVICE_NAME=python-microservice \
    PORT=8000

WORKDIR /app

RUN useradd \
        --create-home \
        --shell /usr/sbin/nologin \
        appuser \
    && rm -rf \
        /usr/local/lib/python3.12/site-packages/pip \
        /usr/local/lib/python3.12/site-packages/pip-* \
        /usr/local/lib/python3.12/ensurepip \
        /usr/local/bin/pip \
        /usr/local/bin/pip3 \
        /usr/local/bin/pip3.12

COPY --from=builder /install/ /usr/local/

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=2s --retries=5 \
    CMD python -c "import http.client; c=http.client.HTTPConnection('127.0.0.1',8000,timeout=2); c.request('GET','/health'); r=c.getresponse(); raise SystemExit(0 if r.status == 200 else 1)"

USER appuser

CMD ["python", "-m", "devsecops_agent.app"]
