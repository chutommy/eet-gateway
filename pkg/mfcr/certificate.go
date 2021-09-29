package mfcr

import (
	"crypto/x509"
	"errors"
	"fmt"
)

var ErrInvalidOrganizationName = errors.New("invalid organization name")

// iCACertificate is the certificate of subordinate CA for issuing qualified
// certificates in PEM format..
// CN = I.CA QUALIFIED 2 CA/RSA 02/2016; SN:  100001006 (5F5E4EE HEX)
// https://www.ica.cz/HCA-qualificate
var iCACertificate = `
-----BEGIN CERTIFICATE-----
MIIHpTCCBY2gAwIBAgIEBfXk7jANBgkqhkiG9w0BAQsFADBwMQswCQYDVQQGEwJD
WjEtMCsGA1UECgwkUHJ2bsOtIGNlcnRpZmlrYcSNbsOtIGF1dG9yaXRhLCBhLnMu
MRkwFwYDVQQDDBBJLkNBIFJvb3QgQ0EvUlNBMRcwFQYDVQQFEw5OVFJDWi0yNjQz
OTM5NTAeFw0xNjAyMTExMjE3MTFaFw0yNjAyMDgxMjE3MTFaMH8xCzAJBgNVBAYT
AkNaMSgwJgYDVQQDDB9JLkNBIFF1YWxpZmllZCAyIENBL1JTQSAwMi8yMDE2MS0w
KwYDVQQKDCRQcnZuw60gY2VydGlmaWthxI1uw60gYXV0b3JpdGEsIGEucy4xFzAV
BgNVBAUTDk5UUkNaLTI2NDM5Mzk1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEAyMALHP/YeXEtOEHHJXTrhOrZWZ5SeX3f8phlvUiCIxoJt2yZ4CI2Y26t
SuD+Ard7c539buJlzoZnuFs6xswvSVJwpwoKF3pflZ5DZjyqUhPpDZdEXQyne1U9
uo1T9wD1WWKQ/yONzKcawxfH2tr0ourILIjVtB6I99u5uA7flA/mynGucR1C4PC9
WbY4MrRV+YkSAzWb88K1wyhVZ0Tq50+jINrL8xCGzRNLSPbMw9lBsWNPfcom2ajP
bmIfyaf3uMBGNdNxUjQoiBjC0mYWkrEd95K6S0dkOA8KgelI/3Kyut/kxc1RsLXg
Io0DNSQ9F38q2I8KWpmxm2sOAHBR191fNEwhnfomCi1jjx6nHpIhHR1Vs5KcjL6z
8Qr42otM55qtEBhOnM1juPZs5+GYjpHG08e9cATWBC3GLd59hN6uSdZjNSb6LVg0
hB194Jb29WpaNj0wzEx98zR1W4NQy+EXSaBfj8bb7UZrxtSoJzF2YMNAPb/oYlRV
NuP4tmnUsW3m6r09j7cltBXCo/YfXDRX0rWNlJ7p+gDRHU1+nPlih6LWgyI/yrhJ
qGg4dg63YyywvuuoDI0zfjlhBSkqQymNwNelg1mDcEFUVxk8LKzXPXJlFNEt33+q
T+CMXlR+IkUC0jOI1SZV3uwcAwgbQWazNljKFpoJjGXc4fwh2A8CAwEAAaOCAjYw
ggIyMIHXBgNVHSAEgc8wgcwwgckGBFUdIAAwgcAwgb0GCCsGAQUFBwICMIGwGoGt
VGVudG8ga3ZhbGlmaWtvdmFueSBzeXN0ZW1vdnkgY2VydGlmaWthdCBieWwgdnlk
YW4gcG9kbGUgemFrb25hIDIyNy8yMDAwIFNiLiB2IHBsYXRuZW0gem5lbmkvVGhp
cyBxdWFsaWZpZWQgc3lzdGVtIGNlcnRpZmljYXRlIHdhcyBpc3N1ZWQgYWNjb3Jk
aW5nIHRvIEFjdCBOby4gMjI3LzIwMDAgQ29sbC4wEgYDVR0TAQH/BAgwBgEB/wIB
ADAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFHSCCJHj2WRocYXW6zHkct+LJrFt
MB8GA1UdIwQYMBaAFHa5A0j71RihoTeg7cxogkxSNDYNMIGMBgNVHR8EgYQwgYEw
KaAnoCWGI2h0dHA6Ly9xY3JsZHAxLmljYS5jei9yY2ExNV9yc2EuY3JsMCmgJ6Al
hiNodHRwOi8vcWNybGRwMi5pY2EuY3ovcmNhMTVfcnNhLmNybDApoCegJYYjaHR0
cDovL3FjcmxkcDMuaWNhLmN6L3JjYTE1X3JzYS5jcmwwYwYIKwYBBQUHAQEEVzBV
MCkGCCsGAQUFBzAChh1odHRwOi8vci5pY2EuY3ovcmNhMTVfcnNhLmNlcjAoBggr
BgEFBQcwAYYcaHR0cDovL29jc3AuaWNhLmN6L3JjYTE1X3JzYTANBgkqhkiG9w0B
AQsFAAOCAgEAELc0LBZqU0XQuG/F43zqtPRspgixVwl4TQBW+9uQXPz0Og3C2Qf7
FHZwlB93EXz9D4jxQwffA0fugp/eRu6eZ6v55tR7M5Vvl3rlBPFVlDs1+8CWLABL
tX61hcXslU1Sdtqi6lGab9pDoBMdvLOky/CLMdQvA01XMEjCUIslT+U6UlCUhGG3
Oh/KBqIORdFcWaseoInsJrBpiAA8+wohMKZGomKSXYlUtuwywZ/GNrkHhJd5nN7a
uEDnM39uAYINSeQ7pHYFtyb4Xik8jOsk5LaQcgC/yOOcVVcZhmPJFamwA+xBhJY+
ynoB7cJyLx2IxiO/7PHSBNsobUaFobfAVNJgoY8X+FYmlcGv5526v8dHH6FEdyq/
0mxeXlFpqLrscfJj4zWNcs8+zmrphCrRgeWrrZkciJ+f6tceW+hdDYtpoHDhpJHn
UJRqc2R67x88t55DL9vjcbGNB8CTOthlOUv1UWzmIVO0FOEomUKy7d6cf4g2qbF6
Fbq9I3WzkYyxlizNmEAFVDhT2YdK19lWK8dlabxjIH9KF1yuhIG71NJWM6EVz905
8ebJcfPdpTRhNkZd+X84+YeFDsxYtOd8Q+L3CmX2Xzj9GrssN9ewTVeW7acSLa5g
cdzAiTUF92rQUfuVwr0zGuvZLnsoLIIsaWrx+pgHcBnL49PVJQV5w4c=
-----END CERTIFICATE-----
`

const (
	// OrganizationName is the legal name that the organization is registered with authority at the national level.
	OrganizationName = "Česká republika - Generální finanční ředitelství"
)

// CAService verifies certificates signed off by the CA.
type CAService interface {
	Verify(crt *x509.Certificate) error
}

type caService struct {
	pool *x509.CertPool
}

// Verify verifies crt certificate.
func (c *caService) Verify(crt *x509.Certificate) error {
	opts := x509.VerifyOptions{
		Roots: c.pool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	}

	if _, err := crt.Verify(opts); err != nil {
		return fmt.Errorf("verify certificate: %w", err)
	}

	if n := crt.Subject.Organization[0]; n != OrganizationName {
		return fmt.Errorf("%s: %w", n, ErrInvalidOrganizationName)
	}

	return nil
}

// NewCAService returns a CAService implementation.
func NewCAService() CAService {
	pool, err := x509.SystemCertPool()
	if err != nil {
		panic(fmt.Errorf("system certificate pool: %w", err))
	}
	if ok := pool.AppendCertsFromPEM([]byte(iCACertificate)); !ok {
		panic("failed to parse root certificate")
	}

	return &caService{
		pool: pool,
	}
}