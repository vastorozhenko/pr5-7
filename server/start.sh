#!/bin/sh
# Два процеси одного застосунку: 8080 - без TLS (лише /health і /echo-http), 8443 - TLS.
uvicorn server.app:app --host 0.0.0.0 --port 8080 &
exec uvicorn server.app:app --host 0.0.0.0 --port 8443 \
  --ssl-keyfile server/certs/server.key --ssl-certfile server/certs/server.crt
