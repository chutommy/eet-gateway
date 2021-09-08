package wsse

import (
	"crypto/rsa"
	"fmt"

	"github.com/ma314smith/signedxml"
)

// SignXML fill the XML digest and signature value with the given private key.
func SignXML(data []byte, pk *rsa.PrivateKey) ([]byte, error) {
	signer, err := signedxml.NewSigner(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse xml: %w", err)
	}

	signer.SetReferenceIDAttribute("Id")
	signedXML, err := signer.Sign(pk)
	if err != nil {
		return nil, fmt.Errorf("sign xml with private key: %w", err)
	}

	return []byte(signedXML), nil
}
