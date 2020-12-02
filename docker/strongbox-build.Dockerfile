ARG CORE_VERSION=latest
ARG BASE_VERSION=latest

FROM provable/ptokens-core:$CORE_VERSION
FROM provable/ptokens-strongbox-base:$BASE_VERSION

LABEL maintainer="Provable Things Ltd. <info@provable.xyz>" \
    description="Deterministically reproduce pTokens Android apps." \
    version="1.1"

COPY --chown=provable:provable --from=0 /root/core /home/provable/core

WORKDIR /home/provable

RUN mkdir .gradle && \
    chown -R provable:provable .gradle && \
    mkdir -p apps/strongbox && \
    chown -R provable:provable apps/strongbox

VOLUME .gradle

VOLUME apps/strongbox

USER provable

WORKDIR /home/provable/apps/strongbox

ENTRYPOINT ["./gradlew"]