package wsse

import (
	"fmt"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

func excC14NCanonicalize(elem *etree.Element) ([]byte, error) {
	err := etreeutils.TransformExcC14n(elem, "")

	if err != nil {
		return nil, fmt.Errorf("transform the element (excC14N): %w", err)
	}

	doc := etree.NewDocument()
	doc.SetRoot(elem.Copy())
	doc.WriteSettings = etree.WriteSettings{
		CanonicalAttrVal: true,
		CanonicalEndTags: true,
		CanonicalText:    true,
	}

	canonical, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("write etree document to bytes: %w", err)
	}

	return canonical, nil
}
