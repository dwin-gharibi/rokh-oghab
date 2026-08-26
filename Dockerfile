ARG OPENRESTY_VERSION=1.27.1.2-0-alpine-fat
ARG ALPINE_VERSION=3.21

FROM openresty/openresty:${OPENRESTY_VERSION} AS runtime-base
RUN apk --no-cache upgrade \
    && rm -rf /var/cache/apk/*
RUN addgroup -g 65532 -S rokh \
    && adduser -u 65532 -S -G rokh -h /nonexistent -s /sbin/nologin rokh \
    && mkdir -p /run/rokh-oghab /etc/rokh-oghab \
    && chown -R 65532:65532 /run/rokh-oghab /etc/rokh-oghab
COPY start.sh /usr/local/bin/ro-start
RUN chmod 0555 /usr/local/bin/ro-start
ENV PATH=/usr/local/openresty/bin:/usr/local/openresty/nginx/sbin:$PATH

FROM runtime-base AS controller
COPY lua /usr/local/rokh-oghab/lua
COPY openresty/controller.conf /usr/local/rokh-oghab/nginx.conf
COPY config/controller.json /etc/rokh-oghab/controller.json
RUN mkdir -p /var/lib/rokh-oghab/versions /tmp/ro-client-body \
    && chown -R 65532:65532 /var/lib/rokh-oghab /tmp/ro-client-body \
    && chmod -R 0555 /usr/local/rokh-oghab/lua
ENV RO_ROLE=controller \
    RO_CONTROLLER_CONFIG=/etc/rokh-oghab/controller.json \
    RO_CONTROLLER_DATA_DIR=/var/lib/rokh-oghab
USER 65532:65532
EXPOSE 8081
VOLUME ["/var/lib/rokh-oghab"]
STOPSIGNAL SIGQUIT
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ro-start healthcheck 8081 || exit 1
ENTRYPOINT ["/usr/local/bin/ro-start"]
CMD ["serve"]

FROM alpine:${ALPINE_VERSION} AS agent
ARG EXTRA_CA_CERT=""
RUN if [ -n "$EXTRA_CA_CERT" ]; then \
        printf '%s' "$EXTRA_CA_CERT" > /usr/local/share/ca-certificates/extra.crt; \
    fi
RUN apk --no-cache upgrade \
    && apk add --no-cache nftables iproute2 ca-certificates \
    && (update-ca-certificates 2>/dev/null || true) \
    && rm -rf /var/cache/apk/*
COPY bin/ro-agent /usr/local/bin/ro-agent
RUN chmod 0555 /usr/local/bin/ro-agent
ENV RO_PROXY_PORT=3128 \
    RO_DNS_PORT=5353 \
    RO_HOOK=forward \
    RO_BLOCK_IPV6=true \
    RO_RECONCILE_SECONDS=15
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ro-agent status >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/usr/local/bin/ro-agent"]
CMD ["run"]

FROM runtime-base AS gateway
COPY lua /usr/local/rokh-oghab/lua
COPY nginx.conf /usr/local/rokh-oghab/nginx.conf
COPY config/gateway.json /etc/rokh-oghab/gateway.json
COPY config/bootstrap-bundle.json /etc/rokh-oghab/bundle.json
RUN chmod -R 0555 /usr/local/rokh-oghab/lua
ENV RO_ROLE=gateway \
    RO_CONFIG=/etc/rokh-oghab/gateway.json \
    RO_BUNDLE_FILE=/etc/rokh-oghab/bundle.json
USER 65532:65532
EXPOSE 3128 3080 3443 5353/udp 5353 9145
STOPSIGNAL SIGQUIT
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ro-start healthcheck 9145 || exit 1
ENTRYPOINT ["/usr/local/bin/ro-start"]
CMD ["serve"]
