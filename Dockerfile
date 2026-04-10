FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml .
COPY standstill/ standstill/

RUN pip install --no-cache-dir build && \
    python -m build --wheel --outdir /dist


FROM python:3.12-slim

LABEL org.opencontainers.image.title="standstill" \
      org.opencontainers.image.description="AWS Control Tower management CLI" \
      org.opencontainers.image.source="https://github.com/dbnz-io/standstill-internal" \
      org.opencontainers.image.licenses="MPL-2.0"

COPY --from=builder /dist/*.whl /dist/
RUN pip install --no-cache-dir /dist/*.whl && rm -rf /dist && \
    useradd -m -u 1000 standstill

WORKDIR /workspace

USER standstill

ENTRYPOINT ["standstill"]
