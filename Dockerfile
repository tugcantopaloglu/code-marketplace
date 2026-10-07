# syntax=docker/dockerfile:experimental

FROM scratch AS binaries
ARG TARGETARCH
COPY ./bin/code-marketplace-linux-$TARGETARCH /opt/code-marketplace

FROM alpine:3.22
COPY --chmod=755 --from=binaries /opt/code-marketplace /opt
COPY LICENSE NOTICE /usr/share/licenses/code-marketplace/
COPY licenses/ /usr/share/licenses/code-marketplace/dependencies/
RUN addgroup -g 10001 marketplace && adduser -D -u 10001 -G marketplace marketplace && mkdir /extensions && chown 10001:10001 /extensions && ln -s /opt/code-marketplace /usr/local/bin/code-marketplace
USER 10001:10001

ENTRYPOINT [ "code-marketplace" ]
CMD [ "server", "--address", "0.0.0.0:8080", "--extensions-dir", "/extensions" ]
