FROM ubuntu:focal

RUN DEBIAN_FRONTEND="noninteractive" apt-get -y update
RUN DEBIAN_FRONTEND="noninteractive" apt-get install -y clang-10 libclang-10-dev cmake curl libelf-dev iproute2 iputils-ping

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN echo 'export PATH=$PATH:~/.cargo/bin' >> ~/.bashrc

COPY startup.sh /startup.sh
ENTRYPOINT ["/startup.sh"]

RUN mkdir -p /rxdp
WORKDIR /rxdp
