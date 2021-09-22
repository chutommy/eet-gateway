.PHONY: gotest
gotest:
	go test -cover -run=. -v ./pkg/...

.PHONY: gobench
gobench:
	go test -bench=. -v ./pkg/...
