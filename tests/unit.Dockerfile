FROM golang:latest

WORKDIR testdir
COPY go.mod .
COPY go.sum .
COPY ./pkg pkg

RUN go mod tidy

ENTRYPOINT ["go", "test", "-run=.", "-v", "./pkg/..."]