FROM provable/android-sdk:29

FROM python:3.6.9-slim-buster

LABEL maintainer="Provable Things Ltd <info@provable.xyz>" \
      description="Downloads the evidence from each specified bridge, \
      verifies the APK pulled from the specified IPFS gateway along   \
      with the returned proof." \
      version="1.3"

RUN groupadd provable && \
    useradd -m -g provable provable && \
    mkdir -p /home/provable/.android/bin/ 

ENV JAVA_HOME /usr/local/openjdk-8

COPY --from=0 --chown=provable:provable \
    /.android/build-tools/28.0.3/apksigner \
    usr/local/bin/
COPY --from=0 --chown=provable:provable \
    /.android/build-tools/28.0.3/lib/apksigner.jar \
    usr/local/bin/

COPY --from=0 --chown=provable:provable \
    $JAVA_HOME \
    $JAVA_HOME

ENV PATH=$PATH:$JAVA_HOME/bin

RUN apt-get update && \
    apt-get install -y \
        jq \
        curl

USER provable

WORKDIR /home/provable

ARG CACHE_PATH="/home/provable/cache"
ARG SRC_PATH="/home/provable/apps/strongbox"

ENV CACHE_PATH=$CACHE_PATH
ENV SRC_PATH=$SRC_PATH

RUN mkdir -p $CACHE_PATH && \
    mkdir -p $SRC_PATH

VOLUME $CACHE_PATH
VOLUME $SRC_PATH

COPY ./src/requirements.txt .

RUN pip install \
        --user \
        --no-warn-script-location \
        --requirement requirements.txt

COPY --chown=provable:provable src ./src

RUN rm -r src/tests && \
    rm src/apkdiff.py

COPY --chown=provable:provable scripts/*.sh ./

ENTRYPOINT ["./run.sh"]