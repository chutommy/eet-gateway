package server

import (
	"github.com/chutommy/eetgateway/pkg/eet"
)

// HTTPRequest represents a binding structure for HTTP requests.
type HTTPRequest struct {
	Hlavicka eet.TrzbaHlavickaType `json:"hlavicka"`
	Trzba    eet.TrzbaDataType     `json:"trzba"`
}

func encodeRequest(req *HTTPRequest) *eet.TrzbaType {
	return &eet.TrzbaType{
		Hlavicka: req.Hlavicka,
		Data:     req.Trzba,
	}
}

// HTTPResponse represents a binding structure for HTTP responses.
type HTTPResponse struct {
	Hlavicka  eet.OdpovedHlavickaType   `json:"hlavicka"`
	Potvrzeni eet.OdpovedPotvrzeniType  `json:"potvrzeni,omitempty"`
	Chyba     eet.OdpovedChybaType      `json:"chyba,omitempty"`
	Varovani  []eet.OdpovedVarovaniType `json:"varovani,omitempty"`
}

func decodeResponse(odpoved *eet.OdpovedType) *HTTPResponse {
	return &HTTPResponse{
		Hlavicka:  odpoved.Hlavicka,
		Potvrzeni: odpoved.Potvrzeni,
		Chyba:     odpoved.Chyba,
		Varovani:  odpoved.Varovani,
	}
}
