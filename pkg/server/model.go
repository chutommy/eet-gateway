package server

import (
	"errors"
	"net/http"

	"github.com/chutommy/eetgateway/pkg/eet"
)

// PingEETResp represents a response structure of HTTP responses for pings.
type PingEETResp struct {
	EETGatewayStatus string `json:"eet_gateway"`
	TaxAdminStatus   string `json:"tax_admin"`
	KeystoreStatus   string `json:"keystore"`
}

func pingEETResp(taxAdmin error, keyStore error) (int, *PingEETResp) {
	online := func(err error) string {
		if err != nil {
			return err.Error()
		}

		return "online"
	}

	code := http.StatusOK
	if taxAdmin != nil || keyStore != nil {
		code = http.StatusServiceUnavailable
	}

	return code, &PingEETResp{
		EETGatewayStatus: "online", // is able to response
		TaxAdminStatus:   online(taxAdmin),
		KeystoreStatus:   online(keyStore),
	}
}

// SendSaleReq represents a binding structure to HTTP requests for sending sales.
type SendSaleReq struct {
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

func sendSaleRequest(req *SendSaleReq) *eet.TrzbaType {
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

// SendSaleResp represents a reponse structure to HTTP sale requests.
type SendSaleResp struct {
	DatOdmit   *eet.DateTime `json:"dat_odmit,omitempty"`
	ChybZprava string        `json:"chyb_zprava,omitempty"`
	ChybKod    int           `json:"chyb_kod,omitempty"`

	DatPrij *eet.DateTime `json:"dat_prij,omitempty"`
	FIK     eet.FikType   `json:"fik,omitempty"`
	BKP     string        `json:"bkp,omitempty"`

	Test     bool                      `json:"test,omitempty"`
	Varovani []eet.OdpovedVarovaniType `json:"varovani,omitempty"`

	Trzba *SendSaleReq `json:"trzba,omitempty"`
}

func sendSaleResponse(req *SendSaleReq, odpoved *eet.OdpovedType) *SendSaleResp {
	if (odpoved.Hlavicka.Datodmit != eet.DateTime{}) {
		return &SendSaleResp{
			DatOdmit:   &odpoved.Hlavicka.Datodmit,
			ChybZprava: odpoved.Chyba.Zprava,
			ChybKod:    odpoved.Chyba.Kod,
			Test:       odpoved.Potvrzeni.Test || odpoved.Chyba.Test,
			Varovani:   odpoved.Varovani,
		}
	}

	return &SendSaleResp{
		DatPrij:  &odpoved.Hlavicka.Datprij,
		FIK:      odpoved.Potvrzeni.Fik,
		BKP:      string(odpoved.Hlavicka.Bkp),
		Test:     odpoved.Potvrzeni.Test,
		Varovani: odpoved.Varovani,

		Trzba: req,
	}
}

// StoreCertReq represents a binding structure to HTTP requests for storing certificate.
type StoreCertReq struct {
	CertID       string `json:"cert_id" binding:"required"`
	CertPassword string `json:"cert_password" binding:""`

	PKCS12Data     []byte `json:"pkcs12_data" binding:"required"`
	PKCS12Password string `json:"pkcs12_password" binding:"required"`
}

// ListCertIDsResp represents a response structure of the certificate IDs for the list request.
type ListCertIDsResp struct {
	CertIDs []string `json:"cert_ids"`
}

// UpdateCertIDReq represents a binding structure to HTTP requests for certificate ID update.
type UpdateCertIDReq struct {
	CertID string `json:"cert_id" binding:"required"`
	NewID  string `json:"new_id" binding:"required,necsfield=CertID"`
}

// UpdateCertPasswordReq represents a binding structure to HTTP requests for password update.
type UpdateCertPasswordReq struct {
	CertID       string `json:"cert_id" binding:"required"`
	CertPassword string `json:"cert_password" binding:"required"`
	NewPassword  string `json:"new_password" binding:"required,necsfield=CertPassword"`
}

// DeleteCertReq represents a binding structure to HTTP requests for deleting certificate.
type DeleteCertReq struct {
	CertID string `json:"cert_id" binding:"required"`
}

// SuccessCertResp represents a response of a successful action related to a specific certificate.
type SuccessCertResp struct {
	CertID string `json:"cert_id"`
}

func successCertResp(id string) *SuccessCertResp {
	return &SuccessCertResp{CertID: id}
}

// GatewayErrResp represents an error returned from the EET Gateway itself, not from the FSCR.
type GatewayErrResp struct {
	GatewayError string `json:"gateway_error"`
}

func gatewayErrResp(err error) (int, *GatewayErrResp) {
	c, e := http.StatusInternalServerError, ErrUnexpectedFailure

	switch {
	case errors.Is(err, eet.ErrCertificateNotFound):
		c, e = http.StatusNotFound, eet.ErrCertificateNotFound
	case errors.Is(err, eet.ErrInvalidCertificatePassword):
		c, e = http.StatusUnauthorized, eet.ErrInvalidCertificatePassword
	case errors.Is(err, eet.ErrIDAlreadyExists):
		c, e = http.StatusConflict, eet.ErrIDAlreadyExists
	case errors.Is(err, eet.ErrInvalidTaxpayersCertificate):
		c, e = http.StatusBadRequest, eet.ErrInvalidTaxpayersCertificate
	case errors.Is(err, eet.ErrFSCRConnection):
		c, e = http.StatusServiceUnavailable, eet.ErrFSCRConnection
	case errors.Is(err, eet.ErrRequestBuild):
		c, e = http.StatusInternalServerError, eet.ErrRequestBuild
	case errors.Is(err, eet.ErrFSCRResponseParse):
		c, e = http.StatusInternalServerError, eet.ErrFSCRResponseParse
	case errors.Is(err, eet.ErrFSCRResponseVerify):
		c, e = http.StatusInternalServerError, eet.ErrFSCRResponseVerify
	case errors.Is(err, eet.ErrCertificateGet):
		c, e = http.StatusInternalServerError, eet.ErrCertificateGet
	case errors.Is(err, eet.ErrCertificateParse):
		c, e = http.StatusInternalServerError, eet.ErrCertificateParse
	case errors.Is(err, eet.ErrCertificateStore):
		c, e = http.StatusInternalServerError, eet.ErrCertificateStore
	case errors.Is(err, eet.ErrCertificateDelete):
		c, e = http.StatusInternalServerError, eet.ErrCertificateDelete
	case errors.Is(err, eet.ErrCertificateUpdateID):
		c, e = http.StatusInternalServerError, eet.ErrCertificateUpdateID
	case errors.Is(err, eet.ErrCertificateUpdatePassword):
		c, e = http.StatusInternalServerError, eet.ErrCertificateUpdatePassword
	case errors.Is(err, eet.ErrCertIDsList):
		c, e = http.StatusInternalServerError, eet.ErrCertIDsList
	case errors.Is(err, eet.ErrRequestDiscarded):
		c, e = http.StatusInternalServerError, eet.ErrRequestDiscarded
	}

	return c, &GatewayErrResp{GatewayError: e.Error()}
}
