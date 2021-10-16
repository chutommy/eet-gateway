package keystore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/go-redis/redis/v8"
)

// ErrRecordNotFound is returned if the searched record can't be found.
var ErrRecordNotFound = errors.New("record not found")

// Service represents a keystore abstraction for a KeyPair management.
type Service interface {
	Store(ctx context.Context, id string, password []byte, kp *KeyPair) error
	Get(ctx context.Context, id string, password []byte) (*KeyPair, error)
	Delete(ctx context.Context, id string) error
}

type redisService struct {
	rdb *redis.Client
}

var (
	certificateField = "certificate"
	privateKeyField  = "private-key"
	saltField        = "salt"
)

func (r *redisService) Store(ctx context.Context, id string, password []byte, kp *KeyPair) error {
	// generate random salt for each reacord
	salt := make([]byte, 256)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate a random salt value: %w", err)
	}

	crt, key, err := kp.encrypt(password, salt)
	if err != nil {
		return fmt.Errorf("encrypt a keypair: %w", err)
	}

	// store in database
	_, err = r.rdb.HSet(ctx, id, map[string]interface{}{
		certificateField: crt,
		privateKeyField:  key,
		saltField:        salt,
	}).Result()
	if err != nil {
		return fmt.Errorf("store certificate in database: %w", err)
	}

	return nil
}

func (r *redisService) Get(ctx context.Context, id string, password []byte) (*KeyPair, error) {
	// read from database
	m, err := r.rdb.HGetAll(ctx, id).Result()
	if err != nil {
		return nil, fmt.Errorf("retrieve stored certificate from database: %w", err)
	}

	// check fields exist
	crt, ok1 := m[certificateField]
	key, ok2 := m[privateKeyField]
	salt, ok3 := m[saltField]
	if !(ok1 && ok2 && ok3) {
		return nil, fmt.Errorf("empty certificate field: %w", ErrRecordNotFound)
	}

	kp := new(KeyPair)
	err = kp.decrypt(password, []byte(salt), []byte(crt), []byte(key))
	if err != nil {
		return nil, fmt.Errorf("decrypt a keypair: %w", err)
	}

	return kp, nil
}

func (r *redisService) Delete(ctx context.Context, id string) error {
	i, err := r.rdb.Del(ctx, id).Result()
	if err != nil {
		return fmt.Errorf("delete record from database: %w", err)
	}

	// check number of deleted records
	if i == 0 {
		return fmt.Errorf("delete record with ID: %s: %w", id, ErrRecordNotFound)
	}

	return nil
}

func NewRedisService(rdb *redis.Client) Service {
	return &redisService{
		rdb: rdb,
	}
}
