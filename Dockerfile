# Pin to a specific patch release. Update deliberately when upgrading Python.
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /build

COPY pyproject.toml LICENSE README.md ./
COPY standstill/ standstill/

RUN pip install build && \
    python -m build --wheel --outdir /dist


# Pin to the same release as the builder.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    HOME=/home/standstill

LABEL org.opencontainers.image.title="standstill" \
      org.opencontainers.image.description="AWS Control Tower management CLI" \
      org.opencontainers.image.source="https://github.com/dbnz-io/standstill" \
      org.opencontainers.image.licenses="MPL-2.0"

# Create a non-root user with a real home directory before installing anything.
RUN useradd -r -u 1000 -s /sbin/nologin -d /home/standstill standstill && \
    mkdir -p /home/standstill /workspace && \
    chown standstill:standstill /home/standstill /workspace

# Install the wheel, then strip pip and setuptools out of the runtime image.
# The CLI does not need a package manager at runtime.
COPY --from=builder /dist/*.whl /tmp/wheel/
RUN pip install /tmp/wheel/*.whl && \
    pip uninstall -y pip setuptools && \
    rm -rf /tmp/wheel

WORKDIR /workspace

USER standstill

ENTRYPOINT ["standstill"]
