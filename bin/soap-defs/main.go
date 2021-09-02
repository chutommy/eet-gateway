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
		filename: "EETXMLSchema.xsd",
	},
	{
		url:      wsdlURL,
		filename: "EETServiceSOAP.wsdl",
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
