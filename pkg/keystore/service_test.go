package keystore_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"math/big"
	"syscall"
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
	m := miniredis.NewMiniRedis()
	err := m.StartAddr(redisAddr)
	require.NoError(t, err)

	ks := keystore.NewRedisService(redis.NewClient(&redis.Options{
		Addr: m.Addr(),
	}))

	return ks, m
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
	certID        = "cert1"
	certID2       = "cert2"
	certIDx       = keystore.ToCertObjectKey(certID)
	certID2x      = keystore.ToCertObjectKey(certID2)
	certPassword  = []byte("secret1")
	certPassword2 = []byte("secret2")
	certKP        = randomKeyPair()
)

func TestRedisService_Ping(t *testing.T) {
	tests := []struct {
		name  string
		setup func(m *miniredis.Miniredis)
		err   error
	}{
		{
			name:  "ok",
			setup: func(m *miniredis.Miniredis) {},
			err:   nil,
		},
		{
			name: "offline",
			setup: func(m *miniredis.Miniredis) {
				m.Close()
			},
			err: syscall.ECONNREFUSED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ks, m := newRedisSvc(t)
			defer m.Close()

			tc.setup(m)

			err := ks.Ping(context.Background())
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestRedisService_Store(t *testing.T) {
	tests := []struct {
		name  string
		setup func(m *miniredis.Miniredis)
		err   error
	}{
		{
			name:  "ok",
			setup: func(m *miniredis.Miniredis) {},
			err:   nil,
		},
		{
			name: "id already used",
			setup: func(m *miniredis.Miniredis) {
				err := m.Set(certIDx, "")
				require.NoError(t, err)
			},
			err: keystore.ErrIDAlreadyExists,
		},
		{
			name: "redis offline",
			setup: func(m *miniredis.Miniredis) {
				m.Close()
			},
			err: syscall.ECONNREFUSED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ks, m := newRedisSvc(t)
			defer m.Close()

			tc.setup(m)

			err := ks.Store(context.Background(), certID, certPassword, certKP)
			if tc.err == nil {
				require.NoError(t, err)

				certVal := m.HGet(certIDx, keystore.PublicKey)
				require.NotEmpty(t, certVal)

				pkVal := m.HGet(certIDx, keystore.PrivateKeyKey)
				require.NotEmpty(t, pkVal)

				saltVal := m.HGet(certIDx, keystore.SaltKey)
				require.NotEmpty(t, saltVal)
			} else {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestRedisService_Get(t *testing.T) {
	tests := []struct {
		name  string
		setup func(m *miniredis.Miniredis)
		err   error
	}{
		{
			name:  "ok",
			setup: func(m *miniredis.Miniredis) {},
			err:   nil,
		},
		{
			name: "id not found",
			setup: func(m *miniredis.Miniredis) {
				ok := m.Del(certIDx)
				require.True(t, ok)
			},
			err: keystore.ErrRecordNotFound,
		},
		{
			name: "incorrect password",
			setup: func(m *miniredis.Miniredis) {
				m.HSet(certIDx, keystore.PrivateKeyKey, "invalid")
			},
			err: keystore.ErrInvalidDecryptionKey,
		},
		{
			name: "offline",
			setup: func(m *miniredis.Miniredis) {
				m.Close()
			},
			err: io.EOF,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ks, m := newRedisSvc(t)
			defer m.Close()

			err := ks.Store(context.Background(), certID, certPassword, certKP)
			require.NoError(t, err)

			tc.setup(m)

			kp, err := ks.Get(context.Background(), certID, certPassword)
			if tc.err == nil {
				require.NoError(t, err)
				equalKeyPairs(t, certKP, kp)
			} else {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestRedisService_List(t *testing.T) {
	tests := []struct {
		name  string
		setup func(m *miniredis.Miniredis)
		err   error
	}{
		{
			name:  "ok",
			setup: func(m *miniredis.Miniredis) {},
			err:   nil,
		},
		{
			name: "offline",
			setup: func(m *miniredis.Miniredis) {
				m.Close()
			},
			err: syscall.ECONNREFUSED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ks, m := newRedisSvc(t)
			defer m.Close()

			err := ks.Store(context.Background(), certID, certPassword, certKP)
			require.NoError(t, err)

			tc.setup(m)

			ids, err := ks.List(context.Background())
			if tc.err == nil {
				require.NoError(t, err)

				require.Len(t, ids, 1)
				require.Equal(t, certIDx, ids[0])
			} else {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestRedisService_UpdateID(t *testing.T) {
	tests := []struct {
		name  string
		setup func(m *miniredis.Miniredis)
		err   error
	}{
		{
			name:  "ok",
			setup: func(m *miniredis.Miniredis) {},
			err:   nil,
		},
		{
			name: "id not found",
			setup: func(m *miniredis.Miniredis) {
				ok := m.Del(certIDx)
				require.True(t, ok)
			},
			err: keystore.ErrRecordNotFound,
		},
		{
			name: "id already used",
			setup: func(m *miniredis.Miniredis) {
				err := m.Set(certID2x, "")
				require.NoError(t, err)
			},
			err: keystore.ErrIDAlreadyExists,
		},
		{
			name: "id not found",
			setup: func(m *miniredis.Miniredis) {
				ok := m.Del(certIDx)
				require.True(t, ok)
			},
			err: keystore.ErrRecordNotFound,
		},
		{
			name: "offline",
			setup: func(m *miniredis.Miniredis) {
				m.Close()
			},
			err: io.EOF,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ks, m := newRedisSvc(t)
			defer m.Close()

			err := ks.Store(context.Background(), certID, certPassword, certKP)
			require.NoError(t, err)

			tc.setup(m)

			err = ks.UpdateID(context.Background(), certID, certID2)
			if tc.err == nil {
				require.NoError(t, err)

				// verify the certificate
				kp, err := ks.Get(context.Background(), certID2, certPassword)
				require.NoError(t, err)

				equalKeyPairs(t, certKP, kp)
			} else {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestRedisService_UpdatePassword(t *testing.T) {
	tests := []struct {
		name  string
		setup func(m *miniredis.Miniredis)
		err   error
	}{
		{
			name:  "ok",
			setup: func(m *miniredis.Miniredis) {},
			err:   nil,
		},
		{
			name: "id not found",
			setup: func(m *miniredis.Miniredis) {
				ok := m.Del(certIDx)
				require.True(t, ok)
			},
			err: keystore.ErrRecordNotFound,
		},
		{
			name: "incorrect password",
			setup: func(m *miniredis.Miniredis) {
				m.HSet(certIDx, keystore.PrivateKeyKey, "invalid")
			},
			err: keystore.ErrInvalidDecryptionKey,
		},
		{
			name: "offline",
			setup: func(m *miniredis.Miniredis) {
				m.Close()
			},
			err: io.EOF,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ks, m := newRedisSvc(t)
			defer m.Close()

			err := ks.Store(context.Background(), certID, certPassword, certKP)
			require.NoError(t, err)

			tc.setup(m)

			err = ks.UpdatePassword(context.Background(), certID, certPassword, certPassword2)
			if tc.err == nil {
				require.NoError(t, err)

				// verify the certificate
				kp, err := ks.Get(context.Background(), certID, certPassword2)
				require.NoError(t, err)

				equalKeyPairs(t, certKP, kp)
			} else {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestRedisService_Delete(t *testing.T) {
	tests := []struct {
		name  string
		setup func(m *miniredis.Miniredis)
		err   error
	}{
		{
			name:  "ok",
			setup: func(m *miniredis.Miniredis) {},
			err:   nil,
		},
		{
			name: "id not found",
			setup: func(m *miniredis.Miniredis) {
				ok := m.Del(certIDx)
				require.True(t, ok)
			},
			err: keystore.ErrRecordNotFound,
		},
		{
			name: "offline",
			setup: func(m *miniredis.Miniredis) {
				m.Close()
			},
			err: syscall.ECONNREFUSED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ks, m := newRedisSvc(t)
			defer m.Close()

			err := ks.Store(context.Background(), certID, certPassword, certKP)
			require.NoError(t, err)

			tc.setup(m)

			err = ks.Delete(context.Background(), certID)
			if tc.err == nil {
				require.NoError(t, err)

				exists := m.Exists(certIDx)
				require.False(t, exists)
			} else {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func equalKeyPairs(t *testing.T, exp, act *keystore.KeyPair) {
	require.Equal(t, exp.Cert, act.Cert)
	require.Equal(t, exp.PK, act.PK)
}
