FROM sds-docker.artifactory.ci.csc.fi/golang:1.27.2@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c AS plugin

WORKDIR /usr/src

COPY go.mod go.sum ./
RUN go mod download && go mod verify

RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install libgrpc-dev build-essential

COPY . .
RUN go build -ldflags=-w -v -o /usr/local/bin/c4ghtransit ./c4ghtransit/cmd/c4ghtransit/main.go

FROM sds-docker.artifactory.ci.csc.fi/golang:1.27.2@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c

RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install git build-essential gdb

RUN mkdir -p $GOPATH/src/github.com/hashicorp && cd $_ && \
    git clone https://github.com/hashicorp/vault.git && \
    cd vault && \
    make bootstrap && \
    make dev && \
    mv /root/vault /vault

WORKDIR /vault

COPY config.json /vault/config/config.json
COPY --from=plugin /usr/local/bin/c4ghtransit /vault/plugins/c4ghtransit

ENTRYPOINT [ "vault" ]

CMD ["server", "-dev"]
