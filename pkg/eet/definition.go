package eet

import (
	"encoding/xml"
	"fmt"
	"time"

	"github.com/beevik/etree"
)

const DateTimeLayout = "2006-01-02T15:04:05-07:00"

// MustParseTime parses time and panic error is met.
func MustParseTime(s string) time.Time {
	t, err := ParseTime(s)
	if err != nil {
		panic(err)
	}

	return t
}

// ParseTime parses time to the correct string format.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(DateTimeLayout, s)
	if err != nil {
		return t, fmt.Errorf("invalid time format: %w", err)
	}

	return t, nil
}

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
