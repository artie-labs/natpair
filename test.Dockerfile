# Tests that need root run on Amazon Linux 2023, the NATs' distribution, with
# its iptables, iproute and conntrackd. Go comes from the official image,
# because Amazon Linux packages an older version.
FROM golang:1.26 AS go

FROM amazonlinux:2023
RUN dnf install -y iptables-nft iproute conntrack-tools procps-ng tar gzip git \
    && dnf clean all
COPY --from=go /usr/local/go /usr/local/go
ENV GOPATH=/go PATH=/usr/local/go/bin:/go/bin:$PATH
WORKDIR /src
