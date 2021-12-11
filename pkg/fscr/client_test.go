package fscr_test

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/stretchr/testify/require"
)

func TestClient_Ping(t *testing.T) {
	tests := []struct {
		name string
		url  string
		ok   bool
	}{
		{
			name: "playground url",
			url:  fscr.PlaygroundURL,
			ok:   true,
		},
		{
			name: "invalid url",
			url:  "invalid",
			ok:   false,
		},
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS13,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fscrClient := fscr.NewClient(httpClient, tc.url)

			err := fscrClient.Ping()
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestClient_Do(t *testing.T) {
	tests := []struct {
		requestFile string
	}{
		{"testdata/CZ00000019.v3.valid.v3.1.1.xml"},
		{"testdata/CZ683555118.v3.valid.v3.1.1.xml"},
		{"testdata/CZ1212121218.v3.valid.v3.1.1.xml"},
	}

	fscrClient := fscr.NewClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS13,
			},
		},
	}, fscr.PlaygroundURL)

	for _, tc := range tests {
		t.Run(tc.requestFile, func(t *testing.T) {
			raw, err := ioutil.ReadFile(tc.requestFile)
			require.NoError(t, err)

			resp, err := fscrClient.Do(context.Background(), raw)
			require.NoError(t, err)
			require.NotEmpty(t, resp)
		})
	}
}
