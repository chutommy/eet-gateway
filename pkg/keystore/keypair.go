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
)

// ErrInvalidNonceSize is returned if then nonce is longer than the encrypted text.
var ErrInvalidNonceSize = errors.New("invalid nonce size")

// KeyPair represents a key pair combination of a private and public key.
type KeyPair struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

func (kp *KeyPair) encrypt(password, salt []byte) (cert []byte, key []byte, err error) {
	gcm, err := gcmCipher(salt, password)
	if err != nil {
		return nil, nil, fmt.Errorf("generate GCM: %w", err)
	}

	// encrypt public key
	derPubKey := kp.Cert.Raw
	cert, err = encryptPEMWithGCM(gcm, "CERTIFICATE", derPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt public key with GCM: %w", err)
	}

	// encrypt private key
	derPrivKey := x509.MarshalPKCS1PrivateKey(kp.Key)
	key, err = encryptPEMWithGCM(gcm, "RSA PRIVATE KEY", derPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt private key with GCM: %w", err)
	}

	return cert, key, nil
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

func (kp *KeyPair) decrypt(password, salt, cert, key []byte) error {
	gcm, err := gcmCipher(salt, password)
	if err != nil {
		return fmt.Errorf("generate GCM cipher: %w", err)
	}

	// certificate
	certPem, err := decryptPemWithGCM(gcm, cert)
	if err != nil {
		return fmt.Errorf("decrypt public key: %w", err)
	}

	kp.Cert, err = x509.ParseCertificate(certPem)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	// private key
	pkPem, err := decryptPemWithGCM(gcm, key)
	if err != nil {
		return fmt.Errorf("decrypt private key: %w", err)
	}

	kp.Key, err = x509.ParsePKCS1PrivateKey(pkPem)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	return nil
}

func decryptPemWithGCM(gcm cipher.AEAD, cipherText []byte) ([]byte, error) {
	nonceSize := gcm.NonceSize()
	// nonce is part of the cipher text and therefore must be smaller
	if len(cipherText) < nonceSize {
		return nil, fmt.Errorf("nonce is longer than cipher text: %w", ErrInvalidNonceSize)
	}

	// split nonce and the cipher
	nonce, sealed := cipherText[:nonceSize], cipherText[nonceSize:]
	// open sealed cipher
	pemData, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("open sealed cipher text: %w", err)
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
