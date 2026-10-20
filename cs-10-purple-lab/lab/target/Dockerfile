# LAB ONLY: static web target for the purple-team lab.
ARG NGINX_IMAGE=nginx:alpine
FROM ${NGINX_IMAGE}
COPY nginx.conf /etc/nginx/nginx.conf
COPY index.html about.html /usr/share/nginx/html/
RUN mkdir -p /logs
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=10 \
    CMD wget -q -O /dev/null http://127.0.0.1/healthz || exit 1
