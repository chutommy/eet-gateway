.PHONY: unit-test
unit-test:
	docker run --rm $$(docker build -f tests/unit/Dockerfile -q .)

.PHONY: unit-test-report
unit-test-report:
	docker run -v "$$PWD/tests/reports":/gen --rm $$(docker build -f tests/unit-report/Dockerfile -q .)

.PHONY: e2e-test
e2e-test:
	docker run --network="host" postman/newman run "https://www.getpostman.com/collections/b9a63360faf9758ea4fc" -n 3

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
	# https://hub.docker.com/r/goreleaser/goreleaser
	docker run --rm --privileged \
      -v $$PWD:/src \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -w /src \
      goreleaser/goreleaser release --snapshot --rm-dist

.PHONY: eet-gens
eet-gens: eet-specs eet-models eet-mocks

.PHONY: eet-specs
eet-specs:
	docker run -v "$$PWD/data/eet-specs":/gen --rm $$(docker build -f gen/specs/Dockerfile -q .)

.PHONY: eet-models
eet-models:
	docker run -v "$$PWD/pkg/eet":/gen --rm $$(docker build -f gen/models/Dockerfile -q .)

.PHONY: eet-mocks
eet-mocks:
	# https://hub.docker.com/r/vektra/mockery
	docker run -v "$$PWD":/src -w /src vektra/mockery --all --dir pkg --keeptree --output pkg/mocks --case snake --note "EETGateway - Tommy Chu"