package keystore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Service represents a keystore abstraction for a KeyPair management.
type Service interface {
	Store(id string, password []byte, kp *KeyPair) error
	Get(id string, password []byte) (*KeyPair, error)
	Delete(id string, password []byte) error
}

type redisService struct {
	crt  []byte
	key  []byte
	salt []byte
}

func (r *redisService) Store(id string, password []byte, kp *KeyPair) error {
	salt := make([]byte, 256)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate a random salt value: %w", err)
	}

	crt, key, err := kp.encrypt(password, salt)
	if err != nil {
		return fmt.Errorf("encrypt a keypair: %w", err)
	}

	r.key = key
	r.crt = crt
	r.salt = salt

	return nil
}

func (r *redisService) Get(id string, password []byte) (*KeyPair, error) {
	kp := new(KeyPair)
	err := kp.decrypt(password, r.salt, r.crt, r.key)
	if err != nil {
		return nil, fmt.Errorf("decrypt a keypair: %w", err)
	}

	return kp, nil
}

func (r *redisService) Delete(id string, password []byte) error {
	panic(errors.New("implement me"))
}

func NewService() Service {
	return &redisService{}
}
