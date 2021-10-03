package eet

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func pkp(plaintext string, pk *rsa.PrivateKey) ([]byte, error) {
	digest := sha256.Sum256([]byte(plaintext))
	pkp, err := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signing PKP: %w", err)
	}

	return pkp, err
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
