FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y git build-essential libpcap-dev

RUN git clone https://github.com/robertdavidgraham/masscan.git

WORKDIR /masscan

RUN make

ENTRYPOINT ["./bin/masscan"]