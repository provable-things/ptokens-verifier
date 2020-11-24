FROM python:3.6.9-slim-buster

LABEL description="Verify that the source code of two \
    compiled APKs matches" \
    version="1.0"

RUN groupadd provable && \
    useradd -m -g provable provable && \
    mkdir -p /home/provable/.android/bin/ 

USER provable

WORKDIR /home/provable

ENV CACHE_PATH="/home/provable/cache"
ENV SRC_PATH="/home/provable/apps/strongbox"


RUN mkdir -p $CACHE_PATH && \
    mkdir -p $SRC_PATH

VOLUME $CACHE_PATH
VOLUME $SRC_PATH

COPY --chown=provable:provable src/apkdiff.py .

ENTRYPOINT ["./apkdiff.py"]