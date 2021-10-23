package eet

import (
	"crypto/rsa"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/beevik/etree"
)

// DateTimeLayout is the chosen layout for the time and date data.
const DateTimeLayout = "2006-01-02T15:04:05-07:00"

// MarshalText encodes CastkaType value to the correct form with two included decimal places.
func (c CastkaType) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("%.2f", float64(c))), nil
}

func (t *TrzbaType) etree() (*etree.Element, error) {
	xmlTrzba, err := xml.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("xml marshal trzba type content: %w", err)
	}

	trzbaDoc := etree.NewDocument()
	if err = trzbaDoc.ReadFromBytes(xmlTrzba); err != nil {
		return nil, fmt.Errorf("load trzba data to etree document: %w", err)
	}

	trzba := trzbaDoc.Root()
	// Overwrite the tag of a value "TrzbaType".
	trzba.Tag = "Trzba"
	trzba.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	trzba.CreateAttr("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
	trzba.CreateAttr("xmlns", "http://fs.mfcr.cz/eet/schema/v3")

	return trzba, nil
}

func (t *TrzbaType) setSecurityCodes(pk *rsa.PrivateKey) error {
	err := t.setPKP(pk)
	if err != nil {
		return fmt.Errorf("set pkp: %w", err)
	}

	t.setBKP(t.KontrolniKody.Pkp.PkpType)

	return nil
}

func (t *TrzbaType) setPKP(pk *rsa.PrivateKey) error {
	pkp, err := pkp(t.plaintext(), pk)
	if err != nil {
		return fmt.Errorf("calculate PKP: %w", err)
	}

	t.KontrolniKody.Pkp.Digest = "SHA256"
	t.KontrolniKody.Pkp.Cipher = "RSA2048"
	t.KontrolniKody.Pkp.Encoding = "base64"
	t.KontrolniKody.Pkp.PkpType = pkp

	return nil
}

func (t *TrzbaType) plaintext() string {
	return fmt.Sprintf(
		"%s|%d|%s|%s|%s|%.2f",
		t.Data.Dicpopl,
		t.Data.Idprovoz,
		t.Data.Idpokl,
		t.Data.Poradcis,
		time.Time(t.Data.Dattrzby).Format(DateTimeLayout),
		t.Data.Celktrzba,
	)
}

func (t *TrzbaType) setBKP(pkp PkpType) {
	t.KontrolniKody.Bkp.Digest = "SHA1"
	t.KontrolniKody.Bkp.Encoding = "base16"
	t.KontrolniKody.Bkp.BkpType = bkp(pkp)
}
