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

	for k := 0; k < 3; k++ {
		err = r.rdb.Watch(ctx, func(tx *redis.Tx) error {
			// check if already exists
			i, err := tx.Exists(ctx, id).Result()
			if err != nil {
				return fmt.Errorf("check if id (%s) exists: %w", id, err)
			}

			if i != 0 {
				return fmt.Errorf("found record with id %s: %w", id, ErrIDAlreadyExists)
			}

			// store in database
			_, err = tx.HSet(ctx, id, map[string]interface{}{
				certificateField: cert,
				privateKeyField:  pk,
				saltField:        salt,
			}).Result()
			if err != nil {
				return fmt.Errorf("store certificate in database: %w", err)
			}

			return nil
		}, id)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		} else if err != nil {
			return fmt.Errorf("transaction failed: %w", err)
		}

		break
	}

	return nil
}

// Get retrieves a Keypair by the id.
func (r *redisService) Get(ctx context.Context, id string, password []byte) (*KeyPair, error) {
	m := make(map[string]string)
	for k := 0; k < 3; k++ {
		err := r.rdb.Watch(ctx, func(tx *redis.Tx) error {
			// check if exists
			i, err := tx.Exists(ctx, id).Result()
			if err != nil {
				return fmt.Errorf("check if id (%s) exists: %w", id, err)
			}

			if i == 0 {
				return fmt.Errorf("not found record with id %s: %w", id, ErrRecordNotFound)
			}

			// read from database
			m, err = tx.HGetAll(ctx, id).Result()
			if err != nil {
				return fmt.Errorf("retrieve stored certificate from database: %w", err)
			}

			return nil
		}, id)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("transaction failed: %w", err)
		}

		break
	}

	salt := []byte(m[saltField])
	cert := []byte(m[certificateField])
	pk := []byte(m[privateKeyField])

	kp := new(KeyPair)
	err := kp.decrypt(password, salt, cert, pk)
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
	for k := 0; k < 3; k++ {
		err := r.rdb.Watch(ctx, func(tx *redis.Tx) error {
			// check if exists
			i, err := tx.Exists(ctx, id).Result()
			if err != nil {
				return fmt.Errorf("check if id (%s) exists: %w", id, err)
			}

			if i == 0 {
				return fmt.Errorf("not found record with id %s: %w", id, ErrRecordNotFound)
			}

			// read from database
			m, err := tx.HGetAll(ctx, id).Result()
			if err != nil {
				return fmt.Errorf("retrieve stored certificate from database: %w", err)
			}

			// decrypt KeyPair with the old password
			salt := []byte(m[saltField])
			cert := []byte(m[certificateField])
			pk := []byte(m[privateKeyField])

			kp := new(KeyPair)
			err = kp.decrypt(oldPassword, salt, cert, pk)
			if err != nil {
				return fmt.Errorf("decrypt a keypair: %w", err)
			}

			// encrypt Keypair with the new password
			cert, pk, err = kp.encrypt(newPassword, salt)
			if err != nil {
				return fmt.Errorf("encrypt a keypair: %w", err)
			}

			// overwrite in database
			_, err = tx.HSet(ctx, id, map[string]interface{}{
				certificateField: cert,
				privateKeyField:  pk,
			}).Result()
			if err != nil {
				return fmt.Errorf("store certificate in database: %w", err)
			}

			return nil
		}, id)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		} else if err != nil {
			return fmt.Errorf("transaction failed: %w", err)
		}

		break
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
