FROM rust:1.46

FROM provable/android-ndk:20.1.5948944

LABEL maintainer="Provable Things Ltd. <info@provable.xyz>" \
    description="Recreate the expected environment to build pTokens \
    Android apps." \
    version="1.0"

RUN groupadd provable && \
    useradd -m -g provable provable

ENV HOME /home/provable
ENV ANDROID_HOME /home/provable/.android

RUN mv /.android $HOME && \
    chown -R provable:provable $ANDROID_HOME

ENV CARGO_HOME=$HOME/.cargo
ENV RUSTUP_HOME=$HOME/.rustup

COPY --chown=provable:provable --from=0 /usr/local/cargo $CARGO_HOME
COPY --chown=provable:provable --from=0 /usr/local/rustup $RUSTUP_HOME 

RUN apt-get update
RUN apt-get install -y \
        build-essential \
        software-properties-common && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

ENV PATH=$PATH:$CARGO_HOME/bin
ENV PATH=$PATH:$RUSTUP_HOME/bin

RUN rustup target add armv7-linux-androideabi