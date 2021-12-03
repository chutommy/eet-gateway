FROM golang:latest

WORKDIR testdir
COPY go.mod .
COPY go.sum .
COPY ./pkg pkg

RUN go mod tidy

RUN go install github.com/vakenbolt/go-test-report@latest
RUN go test -run=. -v -json ./pkg/... | go-test-report -g 10 -s 48x32 -t "EET Gateway - Unit test report" -o ./unit.html

RUN chmod 666 unit.html

CMD ["mv", "unit.html", "/gen"]