package soap

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	productionURL = "https://prod.eet.cz/eet/services/EETServiceSOAP/v3"
	playgroundURL = "https://pg.eet.cz/eet/services/EETServiceSOAP/v3"

	soapAction = "http://fs.mfcr.cz/eet/OdeslaniTrzby"
)

// MFCRClient represents a client that can communicate with the EET server.
type MFCRClient interface {
	Do(ctx context.Context, reqBody []byte) ([]byte, error)
}

type mfcrClient struct {
	c   *http.Client
	url string
}

// NewMFCRClient returns a MFCRClient implementation.
func NewMFCRClient(prod bool) MFCRClient {
	return &mfcrClient{
		c:   http.DefaultClient,
		url: url(prod),
	}
}

func url(prod bool) string {
	if prod {
		return productionURL
	}
	return playgroundURL
}

// Do make a valid SOAP request to the MFCR EET server with the request body reqBody and
// redirect the response body to respBody.
func (c *mfcrClient) Do(ctx context.Context, reqBody []byte) ([]byte, error) {
	req, err := createRequest(ctx, c.url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("construct http request: %w", err)
	}

	resp, err := c.doHTTP(req)
	if err != nil {
		return nil, fmt.Errorf("handle request: %w", err)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if err = resp.Body.Close(); err != nil {
		return nil, fmt.Errorf("close response body: %w", err)
	}

	return respBody, nil
}

func (c *mfcrClient) doHTTP(req *http.Request) (*http.Response, error) {
	resp, err := c.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	return resp, nil
}

func createRequest(ctx context.Context, url string, reqBody []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create a new http request: %w", err)
	}

	req.Header.Set("SOAPAction", soapAction)
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")

	return req, nil
}
