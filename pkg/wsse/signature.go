package wsse

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/beevik/etree"
)

// CalcSignature calculates a signature value of the signedInfo element.
func CalcSignature(pk *rsa.PrivateKey, signedInfo *etree.Element) ([]byte, error) {
	signedInfo.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
	digest, err := CalcDigest(signedInfo.Copy())
	if err != nil {
		return nil, fmt.Errorf("calculate digest of signed info: %w", err)
	}

	rawSig, err := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, digest)
	if err != nil {
		return nil, fmt.Errorf("signing signedInfo digest: %w", err)
	}

	return rawSig, nil
}

// CalcDigest calculates a digest value of the given element.
func CalcDigest(e *etree.Element) ([]byte, error) {
	// canonical, err := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("").Canonicalize(e.Copy())
	// note: The line above is using the package dsig (https://github.com/russellhaering/goxmldsig) to canonicalize
	//       the etree element. The custom excC14NCanonicalize function is used instead for the performance
	//       boost (about 40% faster). Nevertheless, since the custom canonicalizer is heavily inspired by the one
	//       derived from the dsig package, the link to the original code is left for debugging purposes.
	canonical, err := excC14NCanonicalize(e.Copy())
	if err != nil {
		return nil, fmt.Errorf("canonicalize the element (c14n): %w", err)
	}

	hash := crypto.SHA256.New()
	_, err = hash.Write(canonical)
	if err != nil {
		return nil, fmt.Errorf("hash canonicalized element: %w", err)
	}

	return hash.Sum(nil), nil
}
