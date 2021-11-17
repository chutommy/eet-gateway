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
var ErrIDAlreadyExists = errors.New("record with the id already exists")

// ErrReachedMaxAttempts is returned if the maximum number of attempts of transactions is reached.
var ErrReachedMaxAttempts = errors.New("maximum number of attempts reached")

var (
	// IDsObjectKey is the redis object key for storing certificate IDs.
	IDsObjectKey = "ids"
	// CertObjectKey is the redis object key for storing certificates.
	CertObjectKey = "certificate"

	// PublicKey is the redis key of the certificate field.
	PublicKey = "public-key"
	// PrivateKeyKey is the redis key of the private key field.
	PrivateKeyKey = "private-key"
	// SaltKey is the redis key of the salt field.
	SaltKey = "salt"
)

// ToCertObjectKey converts a certificate ID to a keystore object key.
func ToCertObjectKey(id string) string {
	return fmt.Sprintf("%s:%s", CertObjectKey, id)
}

// Service represents a keystore abstraction for KeyPair management.
type Service interface {
	Ping(ctx context.Context) error
	Store(ctx context.Context, id string, password []byte, kp *KeyPair) error
	Get(ctx context.Context, id string, password []byte) (*KeyPair, error)
	List(ctx context.Context, start, end int64) ([]string, error)
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
	idx := ToCertObjectKey(id)

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
		i, err := tx.Exists(ctx, idx).Result()
		if err != nil {
			return fmt.Errorf("check if certificate exists: %w", err)
		}

		if i != 0 {
			return fmt.Errorf("found record with same id: %w", ErrIDAlreadyExists)
		}

		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			// store in database
			_, err = pipe.HSet(ctx, idx, map[string]interface{}{
				PublicKey:     cert,
				PrivateKeyKey: pk,
				SaltKey:       salt,
			}).Result()
			if err != nil {
				return fmt.Errorf("store certificate in database: %w", err)
			}

			// add to the list of certificate IDs
			_, err = pipe.RPush(ctx, IDsObjectKey, id).Result()
			if err != nil {
				return fmt.Errorf("add id to the id list: %w", err)
			}

			return nil
		})
		if err != nil {
			return err
		}

		return nil
	}

	for k := 0; k < 3; k++ {
		err = r.rdb.Watch(ctx, txf, idx, IDsObjectKey)
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
	idx := ToCertObjectKey(id)

	m := make(map[string]string)
	txf := func(tx *redis.Tx) error {
		// check if exists
		i, err := tx.Exists(ctx, idx).Result()
		if err != nil {
			return fmt.Errorf("check if id exists: %w", err)
		}

		if i == 0 {
			return fmt.Errorf("not found record with the id: %w", ErrRecordNotFound)
		}

		// read from database
		m, err = tx.HGetAll(ctx, idx).Result()
		if err != nil {
			return fmt.Errorf("retrieve stored certificate from database: %w", err)
		}

		return nil
	}

	for k := 0; k < 3; k++ {
		err := r.rdb.Watch(ctx, txf, idx, IDsObjectKey)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("transaction failed: %w", err)
		}

		salt := []byte(m[SaltKey])
		cert := []byte(m[PublicKey])
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
func (r *redisService) List(ctx context.Context, start, end int64) ([]string, error) {
	ids, err := r.rdb.LRange(ctx, IDsObjectKey, start, end).Result()
	if err != nil {
		return nil, fmt.Errorf("read all records: %w", err)
	}

	return ids, nil
}

// UpdateID modifies the ID of the record.
func (r *redisService) UpdateID(ctx context.Context, oldID, newID string) error {
	oldIDx := ToCertObjectKey(oldID)
	newIDx := ToCertObjectKey(newID)

	txf := func(tx *redis.Tx) error {
		// check if exists
		i, err := tx.Exists(ctx, oldIDx).Result()
		if err != nil {
			return fmt.Errorf("check if id exists: %w", err)
		}

		if i == 0 {
			return fmt.Errorf("not found record with the id: %w", ErrRecordNotFound)
		}

		// check if the new ID already exists
		i, err = tx.Exists(ctx, newIDx).Result()
		if err != nil {
			return fmt.Errorf("check if new id exists: %w", err)
		}

		if i != 0 {
			return fmt.Errorf("found record with the new id: %w", ErrIDAlreadyExists)
		}

		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			// update ID
			_, err := pipe.Rename(ctx, oldIDx, newIDx).Result()
			if err != nil {
				return fmt.Errorf("rename: %w", err)
			}

			// update the ID in the list of IDs
			_, err = pipe.LRem(ctx, IDsObjectKey, 0, oldID).Result()
			if err != nil {
				return fmt.Errorf("remove id from the id list: %w", err)
			}

			_, err = pipe.RPush(ctx, IDsObjectKey, newID).Result()
			if err != nil {
				return fmt.Errorf("add id to the id list: %w", err)
			}

			return nil
		})
		if err != nil {
			return err
		}

		return nil
	}

	for k := 0; k < 3; k++ {
		err := r.rdb.Watch(ctx, txf, oldIDx, IDsObjectKey)
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
	idx := ToCertObjectKey(id)

	txf := func(tx *redis.Tx) error {
		// check if exists
		i, err := tx.Exists(ctx, idx).Result()
		if err != nil {
			return fmt.Errorf("check if id exists: %w", err)
		}

		if i == 0 {
			return fmt.Errorf("record not found by the id: %w", ErrRecordNotFound)
		}

		// read from database
		m, err := tx.HGetAll(ctx, idx).Result()
		if err != nil {
			return fmt.Errorf("retrieve stored certificate from database: %w", err)
		}

		// decrypt KeyPair with the old password
		salt := []byte(m[SaltKey])
		cert := []byte(m[PublicKey])
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

		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			// overwrite in database
			_, err = pipe.HSet(ctx, idx, map[string]interface{}{
				PublicKey:     cert,
				PrivateKeyKey: pk,
			}).Result()
			if err != nil {
				return fmt.Errorf("store certificate in database: %w", err)
			}

			return nil
		})
		if err != nil {
			return err
		}

		return nil
	}

	for k := 0; k < 3; k++ {
		err := r.rdb.Watch(ctx, txf, idx)
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
	idx := ToCertObjectKey(id)

	txf := func(tx *redis.Tx) error {
		// check if exists
		i, err := tx.Exists(ctx, idx).Result()
		if err != nil {
			return fmt.Errorf("check if id exists: %w", err)
		}

		if i == 0 {
			return fmt.Errorf("not found record with the id: %w", ErrRecordNotFound)
		}

		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			// remove
			_, err := pipe.Del(ctx, idx).Result()
			if err != nil {
				return fmt.Errorf("delete record from database: %w", err)
			}

			// update the ID in the list of IDs
			_, err = pipe.LRem(ctx, IDsObjectKey, 0, id).Result()
			if err != nil {
				return fmt.Errorf("remove id from the ID list: %w", err)
			}

			return nil
		})
		if err != nil {
			return err
		}

		return nil
	}

	for k := 0; k < 3; k++ {
		err := r.rdb.Watch(ctx, txf, idx, IDsObjectKey)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		} else if err != nil {
			return fmt.Errorf("transaction failed: %w", err)
		}

		return nil
	}

	return ErrReachedMaxAttempts
}

// NewRedisService returns an implementation of the Service.
func NewRedisService(rdb *redis.Client) Service {
	return &redisService{
		rdb: rdb,
	}
}
