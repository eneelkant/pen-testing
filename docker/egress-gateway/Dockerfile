# Destination-filtering HTTP CONNECT proxy for scanner worker networks.
# No Docker socket. Dual-homed in Compose (restricted + egress networks).
FROM python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PEN_PROXY_BIND=0.0.0.0 \
    PEN_PROXY_PORT=3128

RUN adduser -D -u 10003 proxyuser
WORKDIR /app
# Shared stdlib-only policy (keep in sync with core/isolation/destination_policy.py).
COPY core/isolation/destination_policy.py /app/destination_policy.py
COPY docker/egress-gateway/proxy_main.py /app/proxy_main.py
USER proxyuser
EXPOSE 3128
CMD ["python", "/app/proxy_main.py"]
