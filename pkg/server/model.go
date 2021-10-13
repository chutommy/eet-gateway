package server

import (
	"github.com/chutommy/eetgateway/pkg/eet"
)

// HTTPRequest represents a binding structure for HTTP requests.
type HTTPRequest struct {
	CertID string `json:"cert,omitempty" binding:"required"`

	UUIDZpravy      eet.UUIDType   `json:"uuid_zpravy" binding:"omitempty,uuid_zpravy"`
	DatOdesl        eet.DateTime   `json:"dat_odesl" binding:""`
	PrvniZaslani    bool           `json:"prvni_zaslani" binding:""`
	Overeni         bool           `json:"overeni" binding:""`
	DICPopl         eet.CZDICType  `json:"dic_popl" binding:"required,dic"`
	DICPoverujiciho eet.CZDICType  `json:"dic_poverujiciho" binding:"omitempty,dic,necsfield=Dicpopl"`
	IDProvoz        int            `json:"id_provoz" binding:"required,id_provoz"`
	IDPokl          eet.String20   `json:"id_pokl" binding:"required,id_pokl"`
	PoradCis        eet.String25   `json:"porad_cis" binding:"required,porad_cis"`
	DatTrzby        eet.DateTime   `json:"dat_trzby" binding:""`
	CelkTrzba       eet.CastkaType `json:"celk_trzba" binding:"required,fin_poloz"`
	ZaklNepodlDPH   eet.CastkaType `json:"zakl_nepodl_dph" binding:"omitempty,fin_poloz"`
	ZaklDan1        eet.CastkaType `json:"zakl_dan1" binding:"omitempty,fin_poloz"`
	Dan1            eet.CastkaType `json:"dan1" binding:"omitempty,fin_poloz"`
	ZaklDan2        eet.CastkaType `json:"zakl_dan2" binding:"omitempty,fin_poloz"`
	Dan2            eet.CastkaType `json:"dan2" binding:"omitempty,fin_poloz"`
	ZaklDan3        eet.CastkaType `json:"zakl_dan3" binding:"omitempty,fin_poloz"`
	Dan3            eet.CastkaType `json:"dan3" binding:"omitempty,fin_poloz"`
	CestSluz        eet.CastkaType `json:"cest_sluz" binding:"omitempty,fin_poloz"`
	PouzitZboz1     eet.CastkaType `json:"pouzit_zboz1" binding:"omitempty,fin_poloz"`
	PouzitZboz2     eet.CastkaType `json:"pouzit_zboz2" binding:"omitempty,fin_poloz"`
	PouzitZboz3     eet.CastkaType `json:"pouzit_zboz3" binding:"omitempty,fin_poloz"`
	UrcenoCerpzZuct eet.CastkaType `json:"urceno_cerp_zuct" binding:"omitempty,fin_poloz"`
	CerpZuct        eet.CastkaType `json:"cerp_zuct" binding:"omitempty,fin_poloz"`
	Rezim           eet.RezimType  `json:"rezim" binding:"omitempty,rezim"`
}

func encodeRequest(req *HTTPRequest) *eet.TrzbaType {
	return &eet.TrzbaType{
		Hlavicka: eet.TrzbaHlavickaType{
			Uuidzpravy:   req.UUIDZpravy,
			Datodesl:     req.DatOdesl,
			Prvnizaslani: req.PrvniZaslani,
			Overeni:      req.Overeni,
		},
		Data: eet.TrzbaDataType{
			Dicpopl:         req.DICPopl,
			Dicpoverujiciho: req.DICPoverujiciho,
			Idprovoz:        req.IDProvoz,
			Idpokl:          req.IDPokl,
			Poradcis:        req.PoradCis,
			Dattrzby:        req.DatTrzby,
			Celktrzba:       req.CelkTrzba,
			Zaklnepodldph:   req.ZaklNepodlDPH,
			Zakldan1:        req.ZaklDan1,
			Dan1:            req.Dan1,
			Zakldan2:        req.ZaklDan2,
			Dan2:            req.Dan2,
			Zakldan3:        req.ZaklDan3,
			Dan3:            req.Dan3,
			Cestsluz:        req.CestSluz,
			Pouzitzboz1:     req.PouzitZboz1,
			Pouzitzboz2:     req.PouzitZboz2,
			Pouzitzboz3:     req.PouzitZboz3,
			Urcenocerpzuct:  req.UrcenoCerpzZuct,
			Cerpzuct:        req.CerpZuct,
			Rezim:           req.Rezim,
		},
	}
}

// HTTPResponse represents a binding structure for HTTP responses.
type HTTPResponse struct {
	GatewayError string                    `json:"gateway_error,omitempty"`
	Dat          *eet.DateTime             `json:"dat,omitempty"`
	Fik          eet.FikType               `json:"fik,omitempty"`
	Zprava       string                    `json:"zprava,omitempty"`
	Kod          int                       `json:"kod,omitempty"`
	Test         bool                      `json:"test,omitempty"`
	Varovani     []eet.OdpovedVarovaniType `json:"varovani,omitempty"`
}

func decodeResponse(err error, odpoved *eet.OdpovedType) *HTTPResponse {
	if err != nil {
		return &HTTPResponse{
			GatewayError: err.Error(),
		}
	} else if odpoved != nil {
		// select the non-empty date/time
		cas := odpoved.Hlavicka.Datprij
		if (cas == eet.DateTime{}) {
			cas = odpoved.Hlavicka.Datodmit
		}

		return &HTTPResponse{
			Dat:      &cas,
			Fik:      odpoved.Potvrzeni.Fik,
			Zprava:   odpoved.Chyba.Zprava,
			Kod:      odpoved.Chyba.Kod,
			Test:     odpoved.Potvrzeni.Test || odpoved.Chyba.Test,
			Varovani: odpoved.Varovani,
		}
	}

	return &HTTPResponse{}
}
