package eet

import (
	"crypto/rsa"

	"github.com/beevik/etree"
)

func (t *TrzbaType) Etree() (*etree.Element, error)            { return t.etree() }
func (t *TrzbaType) SetSecurityCodes(pk *rsa.PrivateKey) error { return t.setSecurityCodes(pk) }

func Pkp(plaintext string, pk *rsa.PrivateKey) ([]byte, error) { return pkp(plaintext, pk) }
func Bkp(pkp PkpType) BkpType                                  { return bkp(pkp) }
func SetDelimiters(bkpB16B []byte) []byte                      { return setDelimiters(bkpB16B) }
