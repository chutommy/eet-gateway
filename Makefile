.PHONY: gotest
gotest:
	go test -run=. -v ./pkg/...

gotest-cover:
	go test -cover -run=. -v ./pkg/...

.PHONY: gobench
gobench:
	go test -bench=. -v ./pkg/...
