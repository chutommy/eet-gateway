package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

const (
	xsdURL  = "https://www.etrzby.cz/assets/cs/prilohy/EETXMLSchema.xsd"
	wsdlURL = "https://www.etrzby.cz/assets/cs/prilohy/EETServiceSOAP.wsdl"
)

type soapDefinition struct {
	url      string
	filename string
}

func (d *soapDefinition) path() string {
	return filepath.Join(dir, d.filename)
}

var defs = []soapDefinition{
	{
		url:      xsdURL,
		filename: "soap-definition/EETXMLSchema.xsd",
	},
	{
		url:      wsdlURL,
		filename: "soap-definition/EETServiceSOAP.wsdl",
	},
	{
		url:      "https://www.etrzby.cz/assets/cs/prilohy/CZ00000019.v3.valid.v3.1.1.xml",
		filename: "sample-requests/CZ00000019.v3.valid.v3.1.1.xml",
	},
	{
		url:      "https://www.etrzby.cz/assets/cs/prilohy/CZ1212121218.v3.valid.v3.1.1.xml",
		filename: "sample-requests/CZ1212121218.v3.valid.v3.1.1.xml",
	},
	{
		url:      "https://www.etrzby.cz/assets/cs/prilohy/CZ683555118.v3.valid.v3.1.1.xml",
		filename: "sample-requests/CZ683555118.v3.valid.v3.1.1.xml",
	},
}

var dir string

func main() {
	flag.StringVar(&dir, "dir", ".", "target directory")
	flag.Parse()

	for _, def := range defs {
		if err := webContentToFile(def.url, def.path()); err != nil {
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
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0666)
}

func webContent(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec
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
