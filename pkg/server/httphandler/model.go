package httphandler

import (
	"errors"
	"net/http"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/gateway"
)

// PingEETResp is a response structure for HTTP pings.
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

// SendSaleReq is a binding request structure for sales.
type SendSaleReq struct {
	CertID       string `json:"cert_id,omitempty" binding:"required"`
	CertPassword string `json:"cert_password,omitempty" binding:"required"`

	UUIDZpravy      eet.UUIDType   `json:"uuid_zpravy" binding:"omitempty,uuid_zpravy"`
	DatOdesl        *eet.DateTime  `json:"dat_odesl,omitempty" binding:""`
	PrvniZaslani    bool           `json:"prvni_zaslani" binding:""`
	Overeni         bool           `json:"overeni" binding:""`
	DICPopl         eet.CZDICType  `json:"dic_popl" binding:"required,dic"`
	DICPoverujiciho eet.CZDICType  `json:"dic_poverujiciho" binding:"omitempty,dic,necsfield=Dicpopl"`
	IDProvoz        int            `json:"id_provoz" binding:"required,id_provoz"`
	IDPokl          eet.String20   `json:"id_pokl" binding:"required,id_pokl"`
	PoradCis        eet.String25   `json:"porad_cis" binding:"required,porad_cis"`
	DatTrzby        *eet.DateTime  `json:"dat_trzby,omitempty" binding:"required"`
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
			Datodesl:     *req.DatOdesl,
			Prvnizaslani: req.PrvniZaslani,
			Overeni:      req.Overeni,
		},
		Data: eet.TrzbaDataType{
			Dicpopl:         req.DICPopl,
			Dicpoverujiciho: req.DICPoverujiciho,
			Idprovoz:        req.IDProvoz,
			Idpokl:          req.IDPokl,
			Poradcis:        req.PoradCis,
			Dattrzby:        *req.DatTrzby,
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

// SendSaleResp is a reponse structure to sale requests.
type SendSaleResp struct {
	CertID string `json:"cert_id"`

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
	certID := req.CertID
	req.CertID, req.CertPassword = "", ""

	if (odpoved.Hlavicka.Datodmit != eet.DateTime{}) {
		return &SendSaleResp{
			CertID:     certID,
			DatOdmit:   &odpoved.Hlavicka.Datodmit,
			ChybZprava: odpoved.Chyba.Zprava,
			ChybKod:    odpoved.Chyba.Kod,
			Test:       odpoved.Potvrzeni.Test || odpoved.Chyba.Test,
			Varovani:   odpoved.Varovani,
		}
	}

	return &SendSaleResp{
		CertID:   certID,
		DatPrij:  &odpoved.Hlavicka.Datprij,
		FIK:      odpoved.Potvrzeni.Fik,
		BKP:      string(odpoved.Hlavicka.Bkp),
		Test:     odpoved.Potvrzeni.Test,
		Varovani: odpoved.Varovani,

		Trzba: req,
	}
}

// StoreCertReq is a binding request structure for storing certificates.
type StoreCertReq struct {
	CertID         string `json:"cert_id" binding:"required"`
	CertPassword   string `json:"cert_password" binding:"required"`
	PKCS12Data     string `json:"pkcs12_data" binding:"required,base64"`
	PKCS12Password string `json:"pkcs12_password" binding:"required"`
}

// ListCertIDsReq is a binding request structure for listing certificate IDs.
type ListCertIDsReq struct {
	Offset int64 `form:"offset" binding:"gte=0"`
	Limit  int64 `form:"limit" binding:"gte=0"`
}

// ListCertIDsResp is a response structure for listing certificate IDs.
type ListCertIDsResp struct {
	CertIDs []string `json:"cert_ids"`
}

// UpdateCertIDURIReq is a URI binding request structure for certificate ID updates.
type UpdateCertIDURIReq struct {
	CertID string `uri:"cert_id" binding:"required"`
}

// UpdateCertIDJSONReq is a JSON binding request structure for certificate ID updates.
type UpdateCertIDJSONReq struct {
	NewID string `json:"new_id" binding:"required"`
}

// UpdateCertPasswordURIReq is a URI binding request structure for password updates.
type UpdateCertPasswordURIReq struct {
	CertID string `uri:"cert_id" binding:"required"`
}

// UpdateCertPasswordJSONReq is a JSON binding request structure for password updates.
type UpdateCertPasswordJSONReq struct {
	CertPassword string `json:"cert_password" binding:"required"`
	NewPassword  string `json:"new_password" binding:"required,necsfield=CertPassword"`
}

// DeleteCertReq is a binding request structure for deleting certificates.
type DeleteCertReq struct {
	CertID string `uri:"cert_id" binding:"required"`
}

// SuccessCertResp is a response of a successful action related to certificate.
type SuccessCertResp struct {
	CertID string `json:"cert_id" example:"d406ccda-1bc5-44ab-a081-af6e8740634c"`
} //@name SuccessResponse

func successCertResp(id string) *SuccessCertResp {
	return &SuccessCertResp{CertID: id}
}

// GatewayErrResp represents an error response structure returned from the EET Gateway API (not from the FSCR).
type GatewayErrResp struct {
	GatewayError string `json:"gateway_error" example:"keystore service unavailable"`
} //@name GatewayErrorResponse

func gatewayErrResp(err error) (int, *GatewayErrResp) {
	c, e := http.StatusInternalServerError, ErrUnexpected

	switch {
	case errors.Is(err, gateway.ErrCertificateNotFound):
		c, e = http.StatusNotFound, gateway.ErrCertificateNotFound
	case errors.Is(err, gateway.ErrInvalidCertificatePassword):
		c, e = http.StatusUnauthorized, gateway.ErrInvalidCertificatePassword
	case errors.Is(err, gateway.ErrIDAlreadyExists):
		c, e = http.StatusConflict, gateway.ErrIDAlreadyExists
	case errors.Is(err, gateway.ErrInvalidTaxpayersCertificate):
		c, e = http.StatusBadRequest, gateway.ErrInvalidTaxpayersCertificate
	case errors.Is(err, gateway.ErrFSCRConnection):
		c, e = http.StatusServiceUnavailable, gateway.ErrFSCRConnection
	case errors.Is(err, gateway.ErrKeystoreUnavailable):
		c, e = http.StatusServiceUnavailable, gateway.ErrKeystoreUnavailable
	case errors.Is(err, gateway.ErrRequestBuild):
		c, e = http.StatusInternalServerError, gateway.ErrRequestBuild
	case errors.Is(err, gateway.ErrFSCRResponseParse):
		c, e = http.StatusInternalServerError, gateway.ErrFSCRResponseParse
	case errors.Is(err, gateway.ErrFSCRResponseVerify):
		c, e = http.StatusInternalServerError, gateway.ErrFSCRResponseVerify
	case errors.Is(err, gateway.ErrCertificateParse):
		c, e = http.StatusInternalServerError, gateway.ErrCertificateParse
	case errors.Is(err, gateway.ErrKeystoreUnexpected):
		c, e = http.StatusInternalServerError, gateway.ErrKeystoreUnexpected
	case errors.Is(err, gateway.ErrMaxTXAttempts):
		c, e = http.StatusInternalServerError, gateway.ErrMaxTXAttempts
	}

	return c, &GatewayErrResp{GatewayError: e.Error()}
}
