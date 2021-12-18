FROM golang:latest

WORKDIR testdir
COPY go.mod .
COPY go.sum .
COPY ./pkg pkg

RUN go mod tidy

RUN go test -run=. -v -coverprofile coverage.out ./...
RUN go tool cover -html coverage.out -o coverage.html

RUN chmod 666 coverage.html

CMD ["mv", "coverage.html", "/gen"]