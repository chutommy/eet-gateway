package keystore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/go-redis/redis/v8"
)

// ErrRecordNotFound is returned if a record can't be found.
var ErrRecordNotFound = errors.New("record not found")

// ErrIDAlreadyExists is returned if an ID is already in use.
var ErrIDAlreadyExists = errors.New("record with the ID already exists")

// ErrReachedMaxAttempts is returned if the maximum number of attempts of transactions is reached.
var ErrReachedMaxAttempts = errors.New("maximum number of attempts reached")

var (
	// CertificateKey is the redis key of the certificate field.
	CertificateKey = "certificate"
	// PrivateKeyKey is the redis key of the private key field.
	PrivateKeyKey = "private-key"
	// SaltKey is the redis key of the salt field.
	SaltKey = "salt"
)

// Service represents a keystore abstraction for KeyPair management.
type Service interface {
	Ping(ctx context.Context) error
	Store(ctx context.Context, id string, password []byte, kp *KeyPair) error
	Get(ctx context.Context, id string, password []byte) (*KeyPair, error)
	List(ctx context.Context) ([]string, error)
	UpdateID(ctx context.Context, oldID, newID string) error
	UpdatePassword(ctx context.Context, id string, oldPassword, newPassword []byte) error
	Delete(ctx context.Context, id string) error
}

type redisService struct {
	rdb *redis.Client
}

// Ping tries to connect to the database and find out whether it is online.
func (r *redisService) Ping(ctx context.Context) error {
	return r.rdb.Ping(ctx).Err()
}

// Store stores the given KeyPair kp in the database encrypted with the password.
func (r *redisService) Store(ctx context.Context, id string, password []byte, kp *KeyPair) error {
	// generate random salt for each record
	salt := make([]byte, 256)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate a random salt value: %w", err)
	}

	cert, pk, err := kp.encrypt(password, salt)
	if err != nil {
		return fmt.Errorf("encrypt a KeyPair: %w", err)
	}

	txf := func(tx *redis.Tx) error {
		// check if already exists
		i, err := tx.Exists(ctx, id).Result()
		if err != nil {
			return fmt.Errorf("check if certificate exists: %w", err)
		}

		if i != 0 {
			return fmt.Errorf("found record with same id: %w", ErrIDAlreadyExists)
		}

		// set
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			// store in database
			_, err = pipe.HSet(ctx, id, map[string]interface{}{
				CertificateKey: cert,
				PrivateKeyKey:  pk,
				SaltKey:        salt,
			}).Result()
			if err != nil {
				return fmt.Errorf("store certificate in database: %w", err)
			}
			return nil
		})
		return err
	}

	for k := 0; k < 3; k++ {
		err = r.rdb.Watch(ctx, txf, id)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		} else if err != nil {
			return fmt.Errorf("transaction failed: %w", err)
		}

		return nil
	}

	return ErrReachedMaxAttempts
}

// Get retrieves a KeyPair by the ID.
func (r *redisService) Get(ctx context.Context, id string, password []byte) (*KeyPair, error) {
	m := make(map[string]string)
	txf := func(tx *redis.Tx) error {
		// check if exists
		i, err := tx.Exists(ctx, id).Result()
		if err != nil {
			return fmt.Errorf("check if ID exists: %w", err)
		}

		if i == 0 {
			return fmt.Errorf("not found record with the id: %w", ErrRecordNotFound)
		}

		// read from database
		m, err = tx.HGetAll(ctx, id).Result()
		if err != nil {
			return fmt.Errorf("retrieve stored certificate from database: %w", err)
		}

		return nil
	}

	for k := 0; k < 3; k++ {
		err := r.rdb.Watch(ctx, txf, id)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("transaction failed: %w", err)
		}

		salt := []byte(m[SaltKey])
		cert := []byte(m[CertificateKey])
		pk := []byte(m[PrivateKeyKey])

		kp := new(KeyPair)
		err = kp.decrypt(password, salt, cert, pk)
		if err != nil {
			return nil, fmt.Errorf("decrypt a KeyPair: %w", err)
		}

		return kp, nil
	}

	return nil, ErrReachedMaxAttempts
}

// List returns all record keys in the database.
func (r *redisService) List(ctx context.Context) ([]string, error) {
	ids, err := r.rdb.Keys(ctx, "*").Result()
	if err != nil {
		return nil, fmt.Errorf("read all records: %w", err)
	}

	return ids, nil
}

// UpdateID modifies the ID of the record.
func (r *redisService) UpdateID(ctx context.Context, oldID, newID string) error {
	txf := func(tx *redis.Tx) error {
		// check if exists
		i, err := tx.Exists(ctx, oldID).Result()
		if err != nil {
			return fmt.Errorf("check if ID exists: %w", err)
		}

		if i == 0 {
			return fmt.Errorf("not found record with the id: %w", ErrRecordNotFound)
		}

		// set
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			ok, err := r.rdb.RenameNX(ctx, oldID, newID).Result()
			if err != nil {
				return fmt.Errorf("rename: %w", err)
			}

			if !ok {
				return fmt.Errorf("failed to rename results: %w", ErrIDAlreadyExists)
			}

			return nil
		})
		return err
	}

	for k := 0; k < 3; k++ {
		err := r.rdb.Watch(ctx, txf, oldID)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		} else if err != nil {
			return fmt.Errorf("transaction failed: %w", err)
		}

		return nil
	}

	return ErrReachedMaxAttempts
}

// UpdatePassword modifies the password for encryption/decryption of the record.
func (r *redisService) UpdatePassword(ctx context.Context, id string, oldPassword, newPassword []byte) error {
	txf := func(tx *redis.Tx) error {
		// check if exists
		i, err := tx.Exists(ctx, id).Result()
		if err != nil {
			return fmt.Errorf("check if ID exists: %w", err)
		}

		if i == 0 {
			return fmt.Errorf("record not found by the id: %w", ErrRecordNotFound)
		}

		// read from database
		m, err := tx.HGetAll(ctx, id).Result()
		if err != nil {
			return fmt.Errorf("retrieve stored certificate from database: %w", err)
		}

		// decrypt KeyPair with the old password
		salt := []byte(m[SaltKey])
		cert := []byte(m[CertificateKey])
		pk := []byte(m[PrivateKeyKey])

		kp := new(KeyPair)
		err = kp.decrypt(oldPassword, salt, cert, pk)
		if err != nil {
			return fmt.Errorf("decrypt a KeyPair: %w", err)
		}

		// encrypt KeyPair with the new password
		cert, pk, err = kp.encrypt(newPassword, salt)
		if err != nil {
			return fmt.Errorf("encrypt a KeyPair: %w", err)
		}

		// set
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			// overwrite in database
			_, err = pipe.HSet(ctx, id, map[string]interface{}{
				CertificateKey: cert,
				PrivateKeyKey:  pk,
			}).Result()
			if err != nil {
				return fmt.Errorf("store certificate in database: %w", err)
			}

			return nil
		})
		return err
	}

	for k := 0; k < 3; k++ {
		err := r.rdb.Watch(ctx, txf, id)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		} else if err != nil {
			return fmt.Errorf("transaction failed: %w", err)
		}

		return nil
	}

	return ErrReachedMaxAttempts
}

// Delete removes the KeyPair with the ID.
func (r *redisService) Delete(ctx context.Context, id string) error {
	i, err := r.rdb.Del(ctx, id).Result()
	if err != nil {
		return fmt.Errorf("delete record from database: %w", err)
	}

	// check number of deleted records
	if i == 0 {
		return fmt.Errorf("delete record by the id: %w", ErrRecordNotFound)
	}

	return nil
}

// NewRedisService returns an implementation of the Service.
func NewRedisService(rdb *redis.Client) Service {
	return &redisService{
		rdb: rdb,
	}
}
