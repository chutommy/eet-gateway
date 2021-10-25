package keystore_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/require"
)

const redisAddr = "127.0.0.1:6380"

func newRedisSvc(t *testing.T) (keystore.Service, *miniredis.Miniredis) {
	// start a redis test server
	mr := miniredis.NewMiniRedis()
	err := mr.StartAddr(redisAddr)
	require.NoError(t, err)

	ks := keystore.NewRedisService(redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	}))

	return ks, mr
}

var defaultCertTmpl = &x509.Certificate{
	SerialNumber:          big.NewInt(1),
	NotBefore:             time.Now(),
	NotAfter:              time.Now().Add(time.Minute),
	BasicConstraintsValid: true,
	KeyUsage:              x509.KeyUsageDigitalSignature,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
}

func randomKeyPair() *keystore.KeyPair {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	der, err := x509.CreateCertificate(rand.Reader, defaultCertTmpl, defaultCertTmpl, pk.Public(), pk)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return &keystore.KeyPair{
		Cert: cert,
		PK:   pk,
	}
}

var (
	certID       = "cert1"
	certPassword = []byte("secret1")
	certKP       = randomKeyPair()
)

func TestRedisService_Ping(t *testing.T) {
	ks, mr := newRedisSvc(t)
	defer mr.Close()

	t.Run("ok", func(t *testing.T) {
		err := ks.Ping(context.Background())
		require.NoError(t, err)
	})

	mr.Close()
	t.Run("redis offline", func(t *testing.T) {
		err := ks.Ping(context.Background())
		require.Error(t, err)
	})
}

func TestRedisService_Store(t *testing.T) {
	ks, mr := newRedisSvc(t)
	defer mr.Close()

	t.Run("ok", func(t *testing.T) {
		err := ks.Store(context.Background(), certID, certPassword, certKP)
		require.NoError(t, err)

		certVal := mr.HGet(certID, keystore.CertificateKey)
		require.NotEmpty(t, certVal)

		pkVal := mr.HGet(certID, keystore.PrivateKeyKey)
		require.NotEmpty(t, pkVal)

		saltVal := mr.HGet(certID, keystore.SaltKey)
		require.NotEmpty(t, saltVal)
	})

	t.Run("id already used", func(t *testing.T) {
		err := ks.Store(context.Background(), certID, certPassword, certKP)
		require.ErrorIs(t, err, keystore.ErrIDAlreadyExists)
	})

	mr.Close()
	t.Run("redis offline", func(t *testing.T) {
		err := ks.Store(context.Background(), certID, certPassword, certKP)
		require.Error(t, err)
	})
}

func TestRedisService_Get(t *testing.T) {
	ks, mr := newRedisSvc(t)
	defer mr.Close()

	{
		err := ks.Store(context.Background(), certID, certPassword, certKP)
		require.NoError(t, err)
	}

	t.Run("ok", func(t *testing.T) {
		kp, err := ks.Get(context.Background(), certID, certPassword)
		require.NoError(t, err)

		equalKeyPairs(t, certKP, kp)
	})

	t.Run("id not found", func(t *testing.T) {
		_, err := ks.Get(context.Background(), "invalid_id", certPassword)
		require.ErrorIs(t, err, keystore.ErrRecordNotFound)
	})

	t.Run("incorrect password", func(t *testing.T) {
		_, err := ks.Get(context.Background(), certID, []byte{})
		require.ErrorIs(t, err, keystore.ErrInvalidDecryptionKey)
	})

	mr.Close()
	t.Run("redis offline", func(t *testing.T) {
		_, err := ks.Get(context.Background(), certID, certPassword)
		require.Error(t, err)
	})
}

func TestRedisService_List(t *testing.T) {
	ks, mr := newRedisSvc(t)
	defer mr.Close()

	{
		err := ks.Store(context.Background(), certID, certPassword, certKP)
		require.NoError(t, err)
	}

	t.Run("ok", func(t *testing.T) {
		ids, err := ks.List(context.Background())
		require.NoError(t, err)

		require.Len(t, ids, 1)
		require.Equal(t, certID, ids[0])
	})

	mr.Close()
	t.Run("redis offline", func(t *testing.T) {
		_, err := ks.List(context.Background())
		require.Error(t, err)
	})
}

func TestRedisService_UpdateID(t *testing.T) {
	ks, mr := newRedisSvc(t)
	defer mr.Close()

	{
		err := ks.Store(context.Background(), certID, certPassword, certKP)
		require.NoError(t, err)
	}

	newCertID := "cert2"

	t.Run("ok", func(t *testing.T) {
		err := ks.UpdateID(context.Background(), certID, newCertID)
		require.NoError(t, err)

		// verify the certificate
		kp, err := ks.Get(context.Background(), newCertID, certPassword)
		require.NoError(t, err)
		equalKeyPairs(t, certKP, kp)

		// return the certificate ID back to the default
		err = ks.UpdateID(context.Background(), newCertID, certID)
		require.NoError(t, err)
	})

	t.Run("id not found", func(t *testing.T) {
		err := ks.UpdateID(context.Background(), "invalid_id", newCertID)
		require.ErrorIs(t, err, keystore.ErrRecordNotFound)
	})

	t.Run("id already used", func(t *testing.T) {
		err := ks.UpdateID(context.Background(), certID, certID)
		require.ErrorIs(t, err, keystore.ErrIDAlreadyExists)
	})

	mr.Close()
	t.Run("redis offline", func(t *testing.T) {
		err := ks.UpdateID(context.Background(), certID, newCertID)
		require.Error(t, err)
	})
}

func TestRedisService_UpdatePassword(t *testing.T) {
	ks, mr := newRedisSvc(t)
	defer mr.Close()

	{
		err := ks.Store(context.Background(), certID, certPassword, certKP)
		require.NoError(t, err)
	}

	newCertPassword := []byte("secret2")

	t.Run("ok", func(t *testing.T) {
		err := ks.UpdatePassword(context.Background(), certID, certPassword, newCertPassword)
		require.NoError(t, err)

		// verify the certificate
		kp, err := ks.Get(context.Background(), certID, newCertPassword)
		require.NoError(t, err)
		equalKeyPairs(t, certKP, kp)

		// return the certificate password back to the default
		err = ks.UpdatePassword(context.Background(), certID, newCertPassword, certPassword)
		require.NoError(t, err)
	})

	t.Run("id not found", func(t *testing.T) {
		err := ks.UpdatePassword(context.Background(), "invalid_id", certPassword, newCertPassword)
		require.ErrorIs(t, err, keystore.ErrRecordNotFound)
	})

	t.Run("incorrect password", func(t *testing.T) {
		err := ks.UpdatePassword(context.Background(), certID, []byte{}, newCertPassword)
		require.ErrorIs(t, err, keystore.ErrInvalidDecryptionKey)
	})

	mr.Close()
	t.Run("redis offline", func(t *testing.T) {
		err := ks.UpdatePassword(context.Background(), certID, certPassword, newCertPassword)
		require.Error(t, err)
	})
}

func TestRedisService_Delete(t *testing.T) {
	ks, mr := newRedisSvc(t)
	defer mr.Close()

	{
		err := ks.Store(context.Background(), certID, certPassword, certKP)
		require.NoError(t, err)
	}

	t.Run("ok", func(t *testing.T) {
		err := ks.Delete(context.Background(), certID)
		require.NoError(t, err)

		exists := mr.Exists(certID)
		require.False(t, exists)
	})

	t.Run("id not found", func(t *testing.T) {
		err := ks.Delete(context.Background(), certID)
		require.ErrorIs(t, err, keystore.ErrRecordNotFound)
	})

	mr.Close()
	t.Run("redis offline", func(t *testing.T) {
		err := ks.Delete(context.Background(), certID)
		require.Error(t, err)
	})
}

func equalKeyPairs(t *testing.T, exp, act *keystore.KeyPair) {
	require.Equal(t, exp.Cert, act.Cert)
	require.Equal(t, exp.PK, act.PK)
}
