.PHONY: coverage-report
coverage-report:
	docker run -t -v "$$PWD/tests/coverage/report":/gen --rm $$(docker build -f tests/coverage/report/Dockerfile -q .)

.PHONY: unit-test
unit-test:
	docker run -t --rm $$(docker build -f tests/unit/Dockerfile -q .)

.PHONY: unit-test-report
unit-test-report:
	docker run -t -v "$$PWD/tests/unit/report":/gen --rm $$(docker build -f tests/unit/report/Dockerfile -q .)

.PHONY: e2e-test
e2e-test:
	# https://hub.docker.com/r/postman/newman/
	docker run -t --network="host" postman/newman run "https://www.getpostman.com/collections/b9a63360faf9758ea4fc"

.PHONY: e2e-test-report
e2e-test-report:
	# https://hub.docker.com/r/dannydainton/htmlextra
	docker run -t --network="host" -v "$$PWD/tests/e2e/report":/etc/newman dannydainton/htmlextra \
	run "https://www.getpostman.com/collections/b9a63360faf9758ea4fc" -n 5 \
	-r htmlextra --reporter-htmlextra-export e2e.html \
	--reporter-htmlextra-testPaging \
	--reporter-htmlextra-browserTitle "EET Gateway - E2E Test Report" \
	--reporter-htmlextra-title "EET Gateway E2E Test Report" \
	--reporter-htmlextra-titleSize 6 \
	--reporter-htmlextra-logs \
	--reporter-htmlextra-timezone "Czechia/Prague"

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
	docker run -t -v "$$PWD/data/eet-specs":/gen --rm $$(docker build -f gen/specs/Dockerfile -q .)

.PHONY: eet-models
eet-models:
	docker run -t -v "$$PWD/pkg/eet":/gen --rm $$(docker build -f gen/models/Dockerfile -q .)

.PHONY: eet-mocks
eet-mocks:
	# https://hub.docker.com/r/vektra/mockery
	docker run -t -v "$$PWD":/src -w /src vektra/mockery --all --dir pkg --keeptree --output pkg/mocks --case snake --note "EETGateway - Tommy Chu"
