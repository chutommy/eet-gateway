package main

//go:generate go run bin/soap-defs/main.go
//go:generate wsdlgen -o pkg/eet/definition-gen.go -pkg eet eet-specs/soap-definition/EETXMLSchema.xsd eet-specs/soap-definition/EETServiceSOAP.wsdl
