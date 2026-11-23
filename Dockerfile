# One image for the API, the dashboard and the one-shot simulator;
# docker-compose.yml picks the command for each service.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first (better layer caching), then the code.
COPY pyproject.toml README.md ./
COPY src ./src
COPY simulator ./simulator
RUN pip install -e .

COPY alembic.ini ./
COPY migrations ./migrations
COPY rules ./rules
COPY dashboard ./dashboard
COPY docs/runbooks ./docs/runbooks
COPY data ./data

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app

EXPOSE 8000 8501
CMD ["uvicorn", "logsentinel.api:app", "--host", "0.0.0.0", "--port", "8000"]
