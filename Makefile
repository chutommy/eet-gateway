.PHONY: eetg-tls
eetg-tls:
	// TODO run from docker
	EETG_SERVER_TLS_ENABLE=1 EETG_SERVER_MUTUAL_TLS_ENABLE=1 EETG_REDIS_TLS_ENABLE=1 eetg serve

.PHONY: redis-server-tls
redis-server-tls:
	docker run --network host -it -v $(PWD)/certs/redis:/certs redis redis-server \
		--tls-cert-file /certs/server/server.crt \
		--tls-key-file /certs/server/server.key \
		--tls-ca-cert-file /certs/client/ca.crt \
		--tls-port 6379 --port 0

.PHONY: redis-client-tls
redis-client-tls:
	docker run --network host -it -v $(PWD)/certs/redis:/certs redis redis-cli \
		--cert /certs/client/client.crt \
		--key /certs/client/client.key \
		--cacert /certs/server/ca.crt \
		--tls

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
	docker run -t --network="host"  -v $(PWD)/certs:/certs postman/newman run "https://www.getpostman.com/collections/b9a63360faf9758ea4fc" \
		--ssl-client-cert /certs/client/client.crt \
		--ssl-client-key /certs/client/client.key \
		--ssl-extra-ca-certs /certs/server/ca.crt

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

.PHONY: gen-certificates
gen-certificates: gen-server-ssl gen-client-ssl gen-redis-server-ssl gen-redis-client-ssl

.PHONY: gen-server-ssl
gen-server-ssl:
	mkdir -p certs/server
	openssl genrsa -out certs/server/ca.key
	openssl req -new -x509 -days 365 -key certs/server/ca.key -subj "/C=CZ/ST=Prague/L=Prague/O=EET Gateway/CN=EETG CA" -out certs/server/ca.crt

	openssl req -newkey rsa:2048 -nodes -keyout certs/server/server.key -subj "/C=CZ/ST=Prague/L=Prague/O=EET Gateway/CN=eetgateway.com" -out certs/server/server.csr
	bash -c 'openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost") -days 365 -in certs/server/server.csr -CA certs/server/ca.crt -CAkey certs/server/ca.key -CAcreateserial -out certs/server/server.crt'

.PHONY: gen-client-ssl
gen-client-ssl:
	mkdir -p certs/client
	openssl genrsa -out certs/client/ca.key
	openssl req -new -x509 -days 365 -key certs/client/ca.key -subj "/C=CZ/ST=Prague/L=Prague/O=EET Gateway/CN=EETG CA" -out certs/client/ca.crt

	openssl req -newkey rsa:2048 -nodes -keyout certs/client/client.key -subj "/C=CZ/ST=Prague/L=Prague/O=EET Gateway/CN=eetgateway.com" -out certs/client/client.csr
	bash -c 'openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost") -days 365 -in certs/client/client.csr -CA certs/client/ca.crt -CAkey certs/client/ca.key -CAcreateserial -out certs/client/client.crt'

.PHONY: gen-redis-server-ssl
gen-redis-server-ssl:
	mkdir -p certs/redis/server
	openssl genrsa -out certs/redis/server/ca.key
	openssl req -new -x509 -days 365 -key certs/redis/server/ca.key -subj "/C=CZ/ST=Prague/L=Prague/O=EET Gateway/CN=EETG CA" -out certs/redis/server/ca.crt

	openssl req -newkey rsa:2048 -nodes -keyout certs/redis/server/server.key -subj "/C=CZ/ST=Prague/L=Prague/O=EET Gateway/CN=eetgateway.com" -out certs/redis/server/server.csr
	bash -c 'openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost") -days 365 -in certs/redis/server/server.csr -CA certs/redis/server/ca.crt -CAkey certs/redis/server/ca.key -CAcreateserial -out certs/redis/server/server.crt'

.PHONY: gen-redis-client-ssl
gen-redis-client-ssl:
	mkdir -p certs/redis/client
	openssl genrsa -out certs/redis/client/ca.key
	openssl req -new -x509 -days 365 -key certs/redis/client/ca.key -subj "/C=CZ/ST=Prague/L=Prague/O=EET Gateway/CN=EETG CA" -out certs/redis/client/ca.crt

	openssl req -newkey rsa:2048 -nodes -keyout certs/redis/client/client.key -subj "/C=CZ/ST=Prague/L=Prague/O=EET Gateway/CN=eetgateway.com" -out certs/redis/client/client.csr
	bash -c 'openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost") -days 365 -in certs/redis/client/client.csr -CA certs/redis/client/ca.crt -CAkey certs/redis/client/ca.key -CAcreateserial -out certs/redis/client/client.crt'
