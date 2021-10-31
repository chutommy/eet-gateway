.PHONY: gotest
gotest:
	go test -run=. -v ./pkg/...

.PHONY: gotest-cover
gotest-cover:
	go test -cover -run=. -v ./pkg/...

.PHONY: gobench
gobench:
	go test -bench=. -v ./pkg/...

.PHONY: eet-gens
eet-gens: eet-specs eet-models eet-mocks

.PHONY: eet-specs
eet-specs:
	go run scripts/soap-defs/main.go -dir data/eet-specs

.PHONY: eet-models
eet-models:
	# https://github.com/droyo/go-xml
	wsdlgen -o pkg/eet/eet-gen.go -pkg eet data/eet-specs/soap-definition/EETXMLSchema.xsd data/eet-specs/soap-definition/EETServiceSOAP.wsdl
	# insert XML chardata attributes for: OdpovedChybaType, OdpovedVarovaniType
	sed -i '52 i Zprava string `xml:",chardata"`' pkg/eet/eet-gen.go
	sed -i '77 i Zprava string `xml:",chardata"`' pkg/eet/eet-gen.go
	go fmt ./...
	# generate custom XML tag for: OdpovedType, TrzbaType, TrzbaKontrolniKodyType
	# https://github.com/fatih/gomodifytags
	gomodifytags -file pkg/eet/eet-gen.go -struct OdpovedType -remove-tags xml -w --quiet
	gomodifytags -file pkg/eet/eet-gen.go -struct OdpovedType -add-tags xml -add-options xml=omitempty -transform pascalcase -w --quiet
	gomodifytags -file pkg/eet/eet-gen.go -struct TrzbaType -remove-tags xml -w --quiet
	gomodifytags -file pkg/eet/eet-gen.go -struct TrzbaType -add-tags xml -transform pascalcase -w --quiet
	gomodifytags -file pkg/eet/eet-gen.go -struct TrzbaKontrolniKodyType -remove-tags xml -w --quiet
	gomodifytags -file pkg/eet/eet-gen.go -struct TrzbaKontrolniKodyType -add-tags xml -transform snakecase -w --quiet

.PHONY: eet-mocks
eet-mocks:
	# https://github.com/vektra/mockery
	mockery --all --dir pkg --keeptree --output pkg/mocks --case snake --note "EETGateway - Tommy Chu"