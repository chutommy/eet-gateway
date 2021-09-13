package eet

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
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

// SetSecurityHashes sets all required control codes of the TrzbaType elements.
func (t *TrzbaType) SetSecurityHashes(pk *rsa.PrivateKey) error {
	err := t.setPkp(pk)
	if err != nil {
		return fmt.Errorf("set pkp: %w", err)
	}

	t.setBkp(t.KontrolniKody.Pkp.PkpType)

	return nil
}

func (t *TrzbaType) setPkp(pk *rsa.PrivateKey) error {
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

func pkp(plaintext string, pk *rsa.PrivateKey) ([]byte, error) {
	digest := sha256.Sum256([]byte(plaintext))
	pkp, err := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signing PKP: %w", err)
	}

	return pkp, err
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

func (t *TrzbaType) setBkp(pkp PkpType) {
	t.KontrolniKody.Bkp.Digest = "SHA1"
	t.KontrolniKody.Bkp.Encoding = "base16"
	t.KontrolniKody.Bkp.BkpType = bkp(pkp)
}

func bkp(pkp PkpType) BkpType {
	digest := sha1.Sum(pkp)
	bkpB16 := hex.EncodeToString(digest[:])
	bkpB16B := []byte(strings.ToUpper(bkpB16))
	bkp := setDelimiters(bkpB16B)

	return BkpType(bkp)
}

func setDelimiters(bkpB16B []byte) []byte {
	bkp := make([]byte, 44)
	delims := 0
	for i, c := range bkpB16B {
		if (i+delims)%9 == 8 {
			bkp[i+delims] = '-'
			delims++
		}
		bkp[i+delims] = c
	}

	return bkp
}
