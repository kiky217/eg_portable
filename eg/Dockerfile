FROM --platform=linux/amd64 python:3.12.15-slim-bookworm@sha256:9901e0a8d75037d8242ed43155cbcb2d1f61be1356383d8054afb59fd50e39c4
WORKDIR /app
COPY requirements.lock .
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements.lock
# Application code and protocol stay root-owned and immutable for the runtime user.
COPY VERSION .
COPY app app
# Only the gateway's runtime imports; never ship disposable CI executors.
COPY tools/high_effect_admission.py tools/signed_hitl_approval.py tools/adapter_liveness.py tools/runtime_source_fingerprint.py tools/capability_catalog.py tools/operator_runtime_registry.py tools/operator_adapter_binding.py tools/
COPY docs docs
RUN useradd -r -u 10001 gateway && mkdir -p /data /evidence /anchor && chown gateway:gateway /data /evidence /anchor
USER gateway
ENV EVALUATION_GATEWAY_DB_PATH=/data/gateway.db EVALUATION_GATEWAY_EVIDENCE_ROOT=/evidence EVALUATION_GATEWAY_ANCHOR_PATH=/anchor/audit.anchor PYTHONDONTWRITEBYTECODE=1
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8765","--no-access-log"]
