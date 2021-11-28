FROM golang:latest AS build

ENV GO111MODULE="on"
ENV CGO_ENABLED="0"

WORKDIR /build
COPY ./scripts/soap-defs/main.go .

RUN go build -o main main.go


FROM alpine:latest AS copy

COPY --from=build /build/main .

ENTRYPOINT ./main -dir /gen