package main

//go:generate go run cmd/soap-defs/main.go -dir data/eet-specs/

// https://github.com/droyo/go-xml
//go:generate wsdlgen -o pkg/eet/eet-gen.go -pkg eet data/eet-specs/soap-definition/EETXMLSchema.xsd data/eet-specs/soap-definition/EETServiceSOAP.wsdl
// https://github.com/fatih/gomodifytags
//go:generate gomodifytags -file pkg/eet/eet-gen.go -struct OdpovedType -remove-tags xml -w --quiet
//go:generate gomodifytags -file pkg/eet/eet-gen.go -struct OdpovedType -add-tags xml -add-options xml=omitempty -transform pascalcase -w --quiet
//go:generate gomodifytags -file pkg/eet/eet-gen.go -struct TrzbaType -remove-tags xml -w --quiet
//go:generate gomodifytags -file pkg/eet/eet-gen.go -struct TrzbaType -add-tags xml -transform pascalcase -w --quiet
//go:generate gomodifytags -file pkg/eet/eet-gen.go -struct TrzbaKontrolniKodyType -remove-tags xml -w --quiet
//go:generate gomodifytags -file pkg/eet/eet-gen.go -struct TrzbaKontrolniKodyType -add-tags xml -transform snakecase -w --quiet
// https://github.com/vektra/mockery
//go:generate mockery --all --dir pkg --output pkg/mocks --case snake --note "EETGateway - Tommy Chu"
