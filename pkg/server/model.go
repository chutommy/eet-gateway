package server

import (
	"fmt"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/google/uuid"
)

// HTTPRequest represents a binding structure for HTTP requests.
type HTTPRequest struct {
	Datodesl        eet.DateTime   `json:"dat_odesl,omitempty"`
	Prvnizaslani    bool           `json:"prvni_zaslani,omitempty"`
	Overeni         bool           `json:"overeni,omitempty"`
	Dicpopl         eet.CZDICType  `json:"dic_popl,omitempty"`
	Dicpoverujiciho eet.CZDICType  `json:"dic_poverujiciho,omitempty"`
	Idprovoz        int            `json:"id_provoz,omitempty"`
	Idpokl          eet.String20   `json:"id_pokl,omitempty"`
	Poradcis        eet.String25   `json:"porad_cis,omitempty"`
	Dattrzby        eet.DateTime   `json:"dat_trzby,omitempty"`
	Celktrzba       eet.CastkaType `json:"celk_trzba,omitempty"`
	Zaklnepodldph   eet.CastkaType `json:"zakl_nepodl_dph,omitempty"`
	Zakldan1        eet.CastkaType `json:"zakl_dan1,omitempty"`
	Dan1            eet.CastkaType `json:"dan1,omitempty"`
	Zakldan2        eet.CastkaType `json:"zakl_dan2,omitempty"`
	Dan2            eet.CastkaType `json:"dan2,omitempty"`
	Zakldan3        eet.CastkaType `json:"zakl_dan3,omitempty"`
	Dan3            eet.CastkaType `json:"dan3,omitempty"`
	Cestsluz        eet.CastkaType `json:"cest_sluz,omitempty"`
	Pouzitzboz1     eet.CastkaType `json:"pouzit_zboz1,omitempty"`
	Pouzitzboz2     eet.CastkaType `json:"pouzit_zboz2,omitempty"`
	Pouzitzboz3     eet.CastkaType `json:"pouzit_zboz3,omitempty"`
	Urcenocerpzuct  eet.CastkaType `json:"urceno_cerp_zuct,omitempty"`
	Cerpzuct        eet.CastkaType `json:"cerp_zuct,omitempty"`
	Rezim           eet.RezimType  `json:"rezim,omitempty"`
}

func encodeRequest(req *HTTPRequest) *eet.TrzbaType {
	uuid, err := uuid.New().MarshalText()
	if err != nil {
		panic(fmt.Errorf("marshal a freshly generated UUID: %w", err))
	}

	return &eet.TrzbaType{
		Hlavicka: eet.TrzbaHlavickaType{
			Uuidzpravy:   eet.UUIDType(uuid),
			Datodesl:     req.Datodesl,
			Prvnizaslani: req.Prvnizaslani,
			Overeni:      req.Overeni,
		},
		Data: eet.TrzbaDataType{
			Dicpopl:         req.Dicpopl,
			Dicpoverujiciho: req.Dicpoverujiciho,
			Idprovoz:        req.Idprovoz,
			Idpokl:          req.Idpokl,
			Poradcis:        req.Poradcis,
			Dattrzby:        req.Dattrzby,
			Celktrzba:       req.Celktrzba,
			Zaklnepodldph:   req.Zaklnepodldph,
			Zakldan1:        req.Zakldan1,
			Dan1:            req.Dan1,
			Zakldan2:        req.Zakldan2,
			Dan2:            req.Dan2,
			Zakldan3:        req.Zakldan3,
			Dan3:            req.Dan3,
			Cestsluz:        req.Cestsluz,
			Pouzitzboz1:     req.Pouzitzboz1,
			Pouzitzboz2:     req.Pouzitzboz2,
			Pouzitzboz3:     req.Pouzitzboz3,
			Urcenocerpzuct:  req.Urcenocerpzuct,
			Cerpzuct:        req.Cerpzuct,
			Rezim:           req.Rezim,
		},
	}
}

// HTTPResponse represents a binding structure for HTTP responses.
type HTTPResponse struct {
	Bkp      eet.BkpType               `json:"bkp,omitempty"`
	Dat      eet.DateTime              `json:"dat,omitempty"`
	Fik      eet.FikType               `json:"fik,omitempty"`
	Zprava   string                    `json:"zprava,omitempty"`
	Kod      int                       `json:"kod,omitempty"`
	Test     bool                      `json:"test,omitempty"`
	Varovani []eet.OdpovedVarovaniType `json:"varovani,omitempty"`
}

func decodeResponse(odpoved *eet.OdpovedType) *HTTPResponse {
	// select the non-empty date/time
	cas := odpoved.Hlavicka.Datprij
	if (cas == eet.DateTime{}) {
		cas = odpoved.Hlavicka.Datodmit
	}

	return &HTTPResponse{
		Bkp:      odpoved.Hlavicka.Bkp,
		Dat:      cas,
		Fik:      odpoved.Potvrzeni.Fik,
		Zprava:   odpoved.Chyba.Zprava,
		Kod:      odpoved.Chyba.Kod,
		Test:     odpoved.Potvrzeni.Test || odpoved.Chyba.Test,
		Varovani: odpoved.Varovani,
	}
}
