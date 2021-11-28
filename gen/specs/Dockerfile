FROM golang:latest AS build
LABEL maintainer="Tommy Chu <tommychu2256@gmail.com>"
LABEL project="EET Gateway"
LABEL type="Models Generation"

ENV GO111MODULE="on"
ENV GOARCH="amd64"
ENV GOOS="linux"
ENV CGO_ENABLED="0"

WORKDIR /build
COPY ./scripts/soap-defs/main.go .

RUN go build -o main main.go


FROM alpine:latest AS copy

COPY --from=build /build/main .

ENTRYPOINT ./main -dir /gen