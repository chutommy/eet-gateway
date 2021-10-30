package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"go.uber.org/multierr"
)

// ErrInvalidDecryptionKey is returned if the given password for the decryption is invalid and can't be used.
var ErrInvalidDecryptionKey = errors.New("given password can't decrypt the message")

// KeyPair represents a combination of a certificate and a private key.
type KeyPair struct {
	Cert *x509.Certificate
	PK   *rsa.PrivateKey
}

func (kp *KeyPair) encrypt(password, salt []byte) (cert []byte, pk []byte, err error) {
	gcm, err := gcmCipher(salt, password)
	if err != nil {
		return nil, nil, fmt.Errorf("generate GCM: %w", err)
	}

	// encrypt certificate
	derCert := kp.Cert.Raw
	cert, err = encryptPEMWithGCM(gcm, "CERTIFICATE", derCert)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt certificate with GCM: %w", err)
	}

	// encrypt private key
	derPK := x509.MarshalPKCS1PrivateKey(kp.PK)
	pk, err = encryptPEMWithGCM(gcm, "RSA PRIVATE KEY", derPK)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt private key with GCM: %w", err)
	}

	return cert, pk, nil
}

func encryptPEMWithGCM(gcm cipher.AEAD, pemType string, data []byte) ([]byte, error) {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: data,
	})

	// random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate a random nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, pemData, nil), nil
}

func (kp *KeyPair) decrypt(password, salt, cert, pk []byte) error {
	gcm, err := gcmCipher(salt, password)
	if err != nil {
		return fmt.Errorf("generate GCM cipher: %w", err)
	}

	// certificate
	certPem, err := decryptPemWithGCM(gcm, cert)
	if err != nil {
		return fmt.Errorf("decrypt certificate: %w", err)
	}

	kp.Cert, err = x509.ParseCertificate(certPem)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	// private key
	pkPem, err := decryptPemWithGCM(gcm, pk)
	if err != nil {
		return fmt.Errorf("decrypt private key: %w", err)
	}

	kp.PK, err = x509.ParsePKCS1PrivateKey(pkPem)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	return nil
}

func decryptPemWithGCM(gcm cipher.AEAD, cipherText []byte) ([]byte, error) {
	nonceSize := gcm.NonceSize()
	// nonce is part of the cipher text and therefore must be smaller
	if len(cipherText) < nonceSize {
		return nil, fmt.Errorf("nonce is longer than cipher text: %w", ErrInvalidDecryptionKey)
	}

	// split nonce and the cipher
	nonce, sealed := cipherText[:nonceSize], cipherText[nonceSize:]
	// open sealed cipher
	pemData, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, multierr.Append(err, ErrInvalidDecryptionKey)
	}

	block, _ := pem.Decode(pemData)

	return block.Bytes, nil
}

func gcmCipher(salt, password []byte) (cipher.AEAD, error) {
	salted := addSalt(salt, password)
	hash := sha256.Sum256(salted)

	c, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, fmt.Errorf("create a new cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("create a GCM cipher mode: %w", err)
	}

	return gcm, nil
}

func addSalt(salt []byte, password []byte) []byte {
	lp := len(password)
	ls := len(salt)

	// concatenate password and salt
	out := make([]byte, lp+ls)
	copy(out[:lp], password)
	copy(out[lp:], salt)

	return out
}
