package eet

import (
	"crypto/rsa"

	"github.com/beevik/etree"
)

func (t *TrzbaType) Etree() (*etree.Element, error)            { return t.etree() }
func (t *TrzbaType) SetSecurityCodes(pk *rsa.PrivateKey) error { return t.setSecurityCodes(pk) }
