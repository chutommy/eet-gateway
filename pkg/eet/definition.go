package eet

import (
	"encoding/xml"
	"fmt"

	"github.com/beevik/etree"
)

// Etree returns the TrzbaType t as an etree.Element.
func (t *TrzbaType) Etree() (*etree.Element, error) {
	tContent, err := xml.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("xml marshal trzba type content: %w", err)
	}

	doc := etree.NewDocument()
	if err = doc.ReadFromBytes(tContent); err != nil {
		return nil, fmt.Errorf("load trzba data to etree document: %w", err)
	}

	trzba := doc.Root()
	trzba.Tag = "Trzba"
	trzba.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	trzba.CreateAttr("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
	trzba.CreateAttr("xmlns", "http://fs.mfcr.cz/eet/schema/v3")

	return trzba, nil
}
