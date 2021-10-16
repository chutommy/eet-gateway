package eet

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/beevik/etree"
)

func (t *TrzbaType) Etree() (*etree.Element, error) {
	return t.etree()
}

func (t *TrzbaType) SetSecurityCodes(pk *rsa.PrivateKey) error {
	return t.setSecurityCodes(pk)
}

func Pkp(plaintext string, pk *rsa.PrivateKey) ([]byte, error) {
	return pkp(plaintext, pk)
}

func Bkp(pkp PkpType) BkpType {
	return bkp(pkp)
}

func SetDelimiters(bkpB16B []byte) []byte {
	return setDelimiters(bkpB16B)
}

func NewRequestEnvelope(t *TrzbaType, cert *x509.Certificate, pk *rsa.PrivateKey) ([]byte, error) {
	return newRequestEnvelope(t, cert, pk)
}

func ParseResponseEnvelope(env []byte) (*OdpovedType, error) {
	return parseResponseEnvelope(env)
}

func VerifyResponse(trzba *TrzbaType, respEnv []byte, odpoved *OdpovedType, verifyCert func(*x509.Certificate) error) error {
	return verifyResponse(trzba, respEnv, odpoved, verifyCert)
}
