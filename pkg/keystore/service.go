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

// ErrIDAlreadyExists is returned if an ID conflict occurs.
var ErrIDAlreadyExists = errors.New("record with the ID already exists")

// Service represents a keystore abstraction for a KeyPair management.
type Service interface {
	Store(ctx context.Context, id string, password []byte, kp *KeyPair) error
	Get(ctx context.Context, id string, password []byte) (*KeyPair, error)
	Delete(ctx context.Context, id string) error
	ChangePassword(ctx context.Context, id string, oldPassword, newPassword []byte) error
	ChangeID(ctx context.Context, oldID, newID string) error
}

type redisService struct {
	rdb *redis.Client
}

var (
	certificateField = "certificate"
	privateKeyField  = "private-key"
	saltField        = "salt"
)

// Store stores the given Keypair kp in the database encrypted with the password.
func (r *redisService) Store(ctx context.Context, id string, password []byte, kp *KeyPair) error {
	// generate random salt for each reacord
	salt := make([]byte, 256)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate a random salt value: %w", err)
	}

	cert, pk, err := kp.encrypt(password, salt)
	if err != nil {
		return fmt.Errorf("encrypt a keypair: %w", err)
	}

	// check if already exists
	i, err := r.rdb.Exists(ctx, id).Result()
	if err != nil {
		return fmt.Errorf("check if id (%s) exists: %w", id, err)
	}

	if i != 0 {
		return fmt.Errorf("found record with id %s: %w", id, ErrIDAlreadyExists)
	}

	// store in database
	_, err = r.rdb.HSet(ctx, id, map[string]interface{}{
		certificateField: cert,
		privateKeyField:  pk,
		saltField:        salt,
	}).Result()
	if err != nil {
		return fmt.Errorf("store certificate in database: %w", err)
	}

	return nil
}

// Get retrieves a Keypair by the id.
func (r *redisService) Get(ctx context.Context, id string, password []byte) (*KeyPair, error) {
	// read from database
	m, err := r.rdb.HGetAll(ctx, id).Result()
	if err != nil {
		return nil, fmt.Errorf("retrieve stored certificate from database: %w", err)
	}

	// check fields exist
	cert, ok1 := m[certificateField]
	pk, ok2 := m[privateKeyField]
	salt, ok3 := m[saltField]
	if !(ok1 && ok2 && ok3) {
		return nil, fmt.Errorf("empty certificate field: %w", ErrRecordNotFound)
	}

	kp := new(KeyPair)
	err = kp.decrypt(password, []byte(salt), []byte(cert), []byte(pk))
	if err != nil {
		return nil, fmt.Errorf("decrypt a keypair: %w", err)
	}

	return kp, nil
}

// Delete removes the Keypair by the id.
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

// ChangePassword changes password for encryption/decryption of the record content.
func (r *redisService) ChangePassword(ctx context.Context, id string, oldPassword, newPassword []byte) error {
	kp, err := r.Get(ctx, id, oldPassword)
	if err != nil {
		return fmt.Errorf("retrieve keypair with old password: %w", err)
	}

	err = r.Delete(ctx, id)
	if err != nil {
		return fmt.Errorf("delete keypair with old password: %w", err)
	}

	err = r.Store(ctx, id, newPassword, kp)
	if err != nil {
		return fmt.Errorf("store keypair with new password: %w", err)
	}

	return nil
}

// ChangeID changes ID of the record.
func (r *redisService) ChangeID(ctx context.Context, oldID, newID string) error {
	ok, err := r.rdb.RenameNX(ctx, oldID, newID).Result()
	if err != nil {
		return fmt.Errorf("rename %s to %s: %w", oldID, newID, err)
	}

	if !ok {
		return fmt.Errorf("failed to rename results: %w", ErrIDAlreadyExists)
	}

	return nil
}

func NewRedisService(rdb *redis.Client) Service {
	return &redisService{
		rdb: rdb,
	}
}
