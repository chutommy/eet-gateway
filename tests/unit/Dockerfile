FROM golang:latest
LABEL maintainer="Tommy Chu <tommychu2256@gmail.com>"
LABEL project="EET Gateway"
LABEL type="Unit Test"

ENV GO111MODULE="on"
ENV GOARCH="amd64"
ENV GOOS="linux"
ENV CGO_ENABLED="0"

WORKDIR testdir
COPY . .
RUN go mod tidy

ENTRYPOINT ["go", "test", "-run=.", "-v", "./pkg/..."]