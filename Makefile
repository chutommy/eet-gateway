.PHONY: unit-tests
unit-tests:
	docker run --rm $$(docker build -f tests/unit/Dockerfile -q .)

.PHONY: install
install:
	go build -o $(GOBIN)/eetg \
	-ldflags "-s -w -X github.com/chutommy/eetgateway/pkg/cmd.eetgOS=myOS \
	-X github.com/chutommy/eetgateway/pkg/cmd.eetgArch=myArch \
	-X github.com/chutommy/eetgateway/pkg/cmd.eetgVersion=0.0.0 \
	-X github.com/chutommy/eetgateway/pkg/cmd.eetgBuildTime=0000-00-00T00:00:00Z" \
	cmd/eetgateway/main.go

.PHONY: release-snapshot
release-snapshot:
	# https://github.com/goreleaser/goreleaser
	go install github.com/goreleaser/goreleaser@latest
	goreleaser release --snapshot --rm-dist

.PHONY: eet-gens
eet-gens: eet-specs eet-models eet-mocks

.PHONY: eet-specs
eet-specs:
	go run scripts/soap-defs/main.go -dir data/eet-specs

.PHONY: eet-models
eet-models:
	docker run -v "$$PWD/pkg/eet":/gen -w /gen $$(docker build -f gen/models/Dockerfile -q .)

.PHONY: eet-mocks
eet-mocks:
	# https://github.com/vektra/mockery
	docker run -v "$$PWD":/src -w /src vektra/mockery --all --dir pkg --keeptree --output pkg/mocks --case snake --note "EETGateway - Tommy Chu"