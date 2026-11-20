# syntax=docker/dockerfile:1

# Stages: build (shared) -> test (pytest + the suite, used by tests/compose.test.yaml) -> base (runtime).
# `base` is last on purpose: a plain `docker build .` gives the runtime image.
# The Python tag is pinned to a patch release. Bump it deliberately, then re-run the tests.
FROM python:3.12.16-slim AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --system --uid 10001 --no-create-home app

WORKDIR /app
# constraints.txt pins every dependency (direct and indirect) to the versions the tests pass with.
COPY pyproject.toml constraints.txt ./
COPY dograh_password_reset ./dograh_password_reset
RUN pip install -c constraints.txt .

# Test image: same build plus pytest and the test suite.
FROM build AS test

RUN pip install -c constraints.txt ".[test]"
COPY tests ./tests
USER app

ENTRYPOINT ["pytest", "-q", "-p", "no:cacheprovider"]

# Runtime image (the default target).
FROM build AS base

USER app
EXPOSE 8080

# Curl-free health probe. BASE_PATH is read from the environment so the probe
# follows the public path the operator configured.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; p = os.environ.get('BASE_PATH', '/password-reset').rstrip('/'); urllib.request.urlopen('http://127.0.0.1:8080' + p + '/healthz', timeout=4)"]

CMD ["uvicorn", "dograh_password_reset.web:app_from_env", "--factory", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
