package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

const (
	xsdURL  = "https://www.etrzby.cz/assets/cs/prilohy/EETXMLSchema.xsd"
	wsdlURL = "https://www.etrzby.cz/assets/cs/prilohy/EETServiceSOAP.wsdl"
)

type soapDefinition struct {
	url  string
	path string
}

var defs = []soapDefinition{
	{
		url:  xsdURL,
		path: "eet-specs/soap-definition/EETXMLSchema.xsd",
	},
	{
		url:  wsdlURL,
		path: "eet-specs/soap-definition/EETServiceSOAP.wsdl",
	},
}

func main() {
	for _, def := range defs {
		if err := webContentToFile(def.url, def.path); err != nil {
			panic(err)
		}
	}
}

func webContentToFile(url, path string) error {
	b, err := webContent(url)
	if err != nil {
		return err
	}

	if err = writeFile(path, b); err != nil {
		return fmt.Errorf("write a new file: %w", err)
	}

	return nil
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

func webContent(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("issue an HTTP GET request: %w", err)
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read web content: %w", err)
	}
	if err = resp.Body.Close(); err != nil {
		return nil, fmt.Errorf("close response body: %w", err)
	}

	return b, nil
}
