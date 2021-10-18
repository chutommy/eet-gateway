package server

import (
	"github.com/chutommy/eetgateway/pkg/eet"
)

// PingEETResponse represents a response structure of HTTP responses for pings.
type PingEETResponse struct {
	EETGatewayStatus string `json:"eet_gateway"`
	TaxAdminStatus   string `json:"tax_admin"`
}

func encodePingEETResponse(taxAdmin string) *PingEETResponse {
	return &PingEETResponse{
		EETGatewayStatus: "online", // is able to response
		TaxAdminStatus:   taxAdmin,
	}
}

// SendSaleRequest represents a binding structure to HTTP requests for sending sales.
type SendSaleRequest struct {
	CertID       string `json:"cert_id,omitempty" binding:"required"`
	CertPassword string `json:"cert_password,omitempty" binding:""`

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

func decodeSendSaleRequest(req *SendSaleRequest) *eet.TrzbaType {
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

// SendSaleResponse represents a reponse structure to HTTP sale requests.
type SendSaleResponse struct {
	GatewayError string `json:"gateway_error,omitempty"`

	DatOdmit   *eet.DateTime `json:"dat_odmit,omitempty"`
	ChybZprava string        `json:"chyb_zprava,omitempty"`
	ChybKod    int           `json:"chyb_kod,omitempty"`

	DatPrij *eet.DateTime `json:"dat_prij,omitempty"`
	FIK     eet.FikType   `json:"fik,omitempty"`
	BKP     string        `json:"bkp,omitempty"`

	Test     bool                      `json:"test,omitempty"`
	Varovani []eet.OdpovedVarovaniType `json:"varovani,omitempty"`

	Trzba *SendSaleRequest `json:"trzba,omitempty"`
}

func encodeSendSaleResponse(err error, req *SendSaleRequest, odpoved *eet.OdpovedType) *SendSaleResponse {
	if err != nil {
		return &SendSaleResponse{
			GatewayError: err.Error(),
		}
	} else if odpoved != nil {
		if (odpoved.Hlavicka.Datodmit != eet.DateTime{}) {
			return &SendSaleResponse{
				DatOdmit:   &odpoved.Hlavicka.Datodmit,
				ChybZprava: odpoved.Chyba.Zprava,
				ChybKod:    odpoved.Chyba.Kod,
				Test:       odpoved.Potvrzeni.Test || odpoved.Chyba.Test,
				Varovani:   odpoved.Varovani,
			}
		}

		return &SendSaleResponse{
			DatPrij:  &odpoved.Hlavicka.Datprij,
			FIK:      odpoved.Potvrzeni.Fik,
			BKP:      string(odpoved.Hlavicka.Bkp),
			Test:     odpoved.Potvrzeni.Test,
			Varovani: odpoved.Varovani,

			Trzba: req,
		}
	}

	return &SendSaleResponse{}
}

// StoreCertRequest represents a binding structure to HTTP requests for storing certificate.
type StoreCertRequest struct {
	CertID       string `json:"cert_id" binding:""`
	CertPassword string `json:"cert_password" binding:""`

	PKCS12Data     []byte `json:"pkcs12_data" binding:"required"`
	PKCS12Password string `json:"pkcs12_password" binding:"required"`
}

// StoreCertResponse represents a response structure to HTTP request for storing certificate .
type StoreCertResponse struct {
	GatewayError string `json:"gateway_error,omitempty"`

	CertID string `json:"cert_id,omitempty"`
}

func encodeStoreCertResponse(err error, id *string) *StoreCertResponse {
	if err != nil {
		return &StoreCertResponse{
			GatewayError: err.Error(),
		}
	} else if id != nil {
		return &StoreCertResponse{
			CertID: *id,
		}
	}

	return &StoreCertResponse{}
}

// DeleteCertRequest represents a binding structure to HTTP requests for deleting certificate.
type DeleteCertRequest struct {
	CertID string `json:"cert_id" binding:"required"`
}

// DeleteCertResponse represents a reponse structure to HTTP delete requests.
type DeleteCertResponse struct {
	GatewayError string `json:"gateway_error,omitempty"`

	CertID string `json:"cert_id,omitempty"`
}

func encodeDeleteCertResponse(err error, id *string) *DeleteCertResponse {
	if err != nil {
		return &DeleteCertResponse{
			GatewayError: err.Error(),
		}
	} else if id != nil {
		return &DeleteCertResponse{
			CertID: *id,
		}
	}

	return &DeleteCertResponse{}
}

// UpdateCertPasswordRequest represents a binding structure to HTTP requests for password update.
type UpdateCertPasswordRequest struct {
	CertID       string `json:"cert_id" binding:"required"`
	CertPassword string `json:"cert_password" binding:"required"`
	NewPassword  string `json:"new_password" binding:"required"`
}

// UpdateCertPasswordResponse represents a reponse structure to HTTP password update requests.
type UpdateCertPasswordResponse struct {
	GatewayError string `json:"gateway_error,omitempty"`

	CertID string `json:"cert_id,omitempty"`
}

func encodeUpdateCertPasswordResponse(err error, id *string) *UpdateCertPasswordResponse {
	if err != nil {
		return &UpdateCertPasswordResponse{
			GatewayError: err.Error(),
		}
	} else if id != nil {
		return &UpdateCertPasswordResponse{
			CertID: *id,
		}
	}

	return &UpdateCertPasswordResponse{}
}

// UpdateCertIDRequest represents a binding structure to HTTP requests for certificate ID update.
type UpdateCertIDRequest struct {
	CertID string `json:"cert_id" binding:"required"`
	NewID  string `json:"new_id" binding:"required,necsfield=ID"`
}

// UpdateCertIDResponse represents a reponse structure to HTTP certificate ID update requests.
type UpdateCertIDResponse struct {
	GatewayError string `json:"gateway_error,omitempty"`

	CertID string `json:"cert_id,omitempty"`
}

func encodeUpdateCertIDResponse(err error, id *string) *UpdateCertIDResponse {
	if err != nil {
		return &UpdateCertIDResponse{
			GatewayError: err.Error(),
		}
	} else if id != nil {
		return &UpdateCertIDResponse{
			CertID: *id,
		}
	}

	return &UpdateCertIDResponse{}
}
