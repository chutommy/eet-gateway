package eet

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// ContentXML returns the XML content of the TrzbaType.
// The element TrzbaType itself isn't included in the result.
func (t *TrzbaType) ContentXML() ([]byte, error) {
	tXML, err := xml.MarshalIndent(t, "        ", "    ")
	if err != nil {
		return nil, fmt.Errorf("xml marshal trzba type content: %w", err)
	}

	split := strings.Split(string(tXML), "\n")
	striped := strings.Join(split[1:len(split)-1], "\n")

	return []byte(striped), nil
}
