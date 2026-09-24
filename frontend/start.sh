#!/bin/sh
set -eu
: "${PORT:=80}"
: "${BACKEND_URL:?BACKEND_URL is required}"
envsubst '${PORT} ${BACKEND_URL}' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf
exec nginx -g "daemon off;"
