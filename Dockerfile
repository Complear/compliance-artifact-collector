# Compliance Artifact Collector. Build with the benchmark checkout as a named context:
#   docker build --build-context benchmark=../aiod-compliance-benchmark -t compliance-artifact-collector:0.3.2 .
FROM ghcr.io/sigstore/cosign/cosign:v2.4.1 AS cosign

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/Complear/compliance-artifact-collector" \
      org.opencontainers.image.description="Compliance Artifact Collector: one conformity record from an AI system's compliance evidence" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
COPY --from=benchmark pyproject.toml /src/cdb/pyproject.toml
COPY --from=benchmark cdb /src/cdb/cdb
RUN pip install --no-cache-dir jsonschema==4.26.0 /src/cdb && rm -rf /src
WORKDIR /app
COPY cac cac
COPY schema schema
WORKDIR /work
ENV PYTHONPATH=/app
ENTRYPOINT ["python", "-m", "cac"]
CMD ["--help"]
