# Destination-filtering HTTP CONNECT proxy for scanner worker networks.
# No Docker socket. Dual-homed in Compose (restricted + egress networks).
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PEN_PROXY_BIND=0.0.0.0 \
    PEN_PROXY_PORT=3128

RUN useradd --create-home --uid 10003 proxyuser
WORKDIR /app
# Shared stdlib-only policy (keep in sync with core/isolation/destination_policy.py).
COPY core/isolation/destination_policy.py /app/destination_policy.py
COPY docker/egress-gateway/proxy_main.py /app/proxy_main.py
USER proxyuser
EXPOSE 3128
CMD ["python", "/app/proxy_main.py"]
