package wsse_test

import (
	"encoding/pem"
	"io/ioutil"
	"testing"

	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/stretchr/testify/require"
)

type certificate struct {
	filepath string
	binary   string
}

var certs = []certificate{
	{
		filepath: "testdata/EET_CA1_Playground-CZ00000019.crt",
		binary:   "MIIEmTCCA4GgAwIBAgIFAKCnuv0wDQYJKoZIhvcNAQELBQAwdzESMBAGCgmSJomT8ixkARkWAkNaMUMwQQYDVQQKDDrEjGVza8OhIFJlcHVibGlrYSDigJMgR2VuZXLDoWxuw60gZmluYW7EjW7DrSDFmWVkaXRlbHN0dsOtMRwwGgYDVQQDExNFRVQgQ0EgMSBQbGF5Z3JvdW5kMB4XDTE5MDgwODE5MjM0MloXDTIyMDgwODE5MjM0MlowQzESMBAGCgmSJomT8ixkARkWAkNaMRMwEQYDVQQDEwpDWjAwMDAwMDE5MRgwFgYDVQQNEw9wcmF2bmlja2Egb3NvYmEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDrVmZ6FE2jYqli43/LbXZ1vEG8USMRcC/zbGgk5mAoQQKMtF5PIm5i84pd0cPOSRtduNODc7mwjbPKd5r8p592zNhpei0/XbQcYQ5rpdf0Y84ZNbg9ZmB4nF8YCBy3Gk28YxfW//vIjqvkuQK6InT4l784gtz/iNAV48ZBkgE/jp+MMii1I+y5EyYkQuRZlCJtOTKdPXECnr5OrxrGUtbjmF7bBWLD2LXlspZoUOmh4RFfd9WHH8PmcQfij5aJq6cgIB2YENCBHSA1/HZZEd8vNLv05owb/BOvXj4n86lYJ8tlJVMcorAsrEzVy+XU++78/j9PewL0ft0jETHd0U8DAgMBAAGjggFeMIIBWjAJBgNVHRMEAjAAMB0GA1UdDgQWBBT8zaUMxlfEGXSD/2PZ089ZLGgerTAfBgNVHSMEGDAWgBR8MHaszNaH0ezJH+JwCCzjX94MBzAOBgNVHQ8BAf8EBAMCBsAwYwYDVR0gBFwwWjBYBgpghkgBZQMCATABMEowSAYIKwYBBQUHAgIwPAw6VGVudG8gY2VydGlmaWvDoXQgYnlsIHZ5ZMOhbiBwb3V6ZSBwcm8gdGVzdG92YWPDrSDDusSNZWx5LjCBlwYDVR0fBIGPMIGMMIGJoIGGoIGDhilodHRwOi8vY3JsLmNhMS1wZy5lZXQuY3ovZWV0Y2ExcGcvYWxsLmNybIYqaHR0cDovL2NybDIuY2ExLXBnLmVldC5jei9lZXRjYTFwZy9hbGwuY3JshipodHRwOi8vY3JsMy5jYTEtcGcuZWV0LmN6L2VldGNhMXBnL2FsbC5jcmwwDQYJKoZIhvcNAQELBQADggEBAKVFyv168b/q0X568G+JDvNnz4XVElbJ1r9ro/xv58QP+FD8PJSR5qxN2F7zKGNYTCee0jSo+XY1KEoSkmeoYHXnQpm7+NG7iUYc2OWu0B3hC/wMMhNEDtmsTwqSLjgSk6pZTTRXfvtaHf7zvU8iw1PGFhb9m9bJlOfLwoMeFclOpdfo80pbwRz5t8io/c0lvGodlYj7INHxjlwdwWf3m2mUx4iuKvoAev0ASCdSMDuUWWjYiMT3PEUqeabeM2dn3xccQ2EhgIcCwhQs2MCA/FDLBbiOt63mUJPJHATIFi/31VKtz11/Gc434HHsVYB8U/aammSyIfMp6bNE6LhaFe8=",
	},
	{
		filepath: "testdata/EET_CA1_Playground-CZ683555118.crt",
		binary:   "MIIEljCCA36gAwIBAgIEO3d2yTANBgkqhkiG9w0BAQsFADB3MRIwEAYKCZImiZPyLGQBGRYCQ1oxQzBBBgNVBAoMOsSMZXNrw6EgUmVwdWJsaWthIOKAkyBHZW5lcsOhbG7DrSBmaW5hbsSNbsOtIMWZZWRpdGVsc3R2w60xHDAaBgNVBAMTE0VFVCBDQSAxIFBsYXlncm91bmQwHhcNMTkwODA4MTkyNTE4WhcNMjIwODA4MTkyNTE4WjBBMRIwEAYKCZImiZPyLGQBGRYCQ1oxFDASBgNVBAMTC0NaNjgzNTU1MTE4MRUwEwYDVQQNEwxjaXNsbyBwbGF0Y2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCInVe1r3NDkoNvVmTLctn+uq60Gc6fTG0EYB4J8NdNh192Jep0hzYyc87hY9q8/knS9tXyzyXYk2aCEReojleFGsHjhRZxYG8kUlsVjTcudia45p954kwyaz6L+9703kKTPMQX7sRnnYo3uAWxXJa46+a7XjI7FMkd88GMObtcgnlhS6xjNNYa1edgV2ChBcOFN9cZjMeFWdLwNUMNopbO3ZIvcfybedv9bKJhdD/nI4+2mpGyJrlko3E2uNlEoMOCg8+fjHLf6rKHmjK+WGO4l8JRGZkUFmdfhCvH6lPF1xyR8Kn1IBZYRQzBOK1aCq8MBuFG8uF+U/4eXAvKWMsNAgMBAAGjggFeMIIBWjAJBgNVHRMEAjAAMB0GA1UdDgQWBBQy13ecdxpE4MDCW8H7iz8Id+iPdjAfBgNVHSMEGDAWgBR8MHaszNaH0ezJH+JwCCzjX94MBzAOBgNVHQ8BAf8EBAMCBsAwYwYDVR0gBFwwWjBYBgpghkgBZQMCATABMEowSAYIKwYBBQUHAgIwPAw6VGVudG8gY2VydGlmaWvDoXQgYnlsIHZ5ZMOhbiBwb3V6ZSBwcm8gdGVzdG92YWPDrSDDusSNZWx5LjCBlwYDVR0fBIGPMIGMMIGJoIGGoIGDhilodHRwOi8vY3JsLmNhMS1wZy5lZXQuY3ovZWV0Y2ExcGcvYWxsLmNybIYqaHR0cDovL2NybDIuY2ExLXBnLmVldC5jei9lZXRjYTFwZy9hbGwuY3JshipodHRwOi8vY3JsMy5jYTEtcGcuZWV0LmN6L2VldGNhMXBnL2FsbC5jcmwwDQYJKoZIhvcNAQELBQADggEBAJqMAjTujbyYfaOg17Z3m+PC3ksRlow/dClmNFMdALOvoNzhHW4kzviLrTacwUKYzLvqLtrLGqZXdJNk8tSoCmXxbsRSCUKq3N0HB6A/0pN4YuvFxtLDss9FvMs9uZXmXl1VSE43vDb5a8hRBN4BNF+tSnmOXZBLtI22XsgobvKJNuX+nw9w0izLBw67MsqNoSOLTncAFhkuWlJd9B7jaRgBBTp5SilqEDrhjI752bJ3Xp24+Hvka3NyFZOsqmSdmirse4lxQY+iHTq0w+fnMa/oT4lQUhqmbVAsttl4BZC+lWCBAUS5ri4CNVzA4oGHd+zSYGen/dvZz+ZnLSJSDcc=",
	},
	{
		filepath: "testdata/EET_CA1_Playground-CZ1212121218.crt",
		binary:   "MIIEmDCCA4CgAwIBAgIEMZKS4zANBgkqhkiG9w0BAQsFADB3MRIwEAYKCZImiZPyLGQBGRYCQ1oxQzBBBgNVBAoMOsSMZXNrw6EgUmVwdWJsaWthIOKAkyBHZW5lcsOhbG7DrSBmaW5hbsSNbsOtIMWZZWRpdGVsc3R2w60xHDAaBgNVBAMTE0VFVCBDQSAxIFBsYXlncm91bmQwHhcNMTkwODA4MTkyNjEwWhcNMjIwODA4MTkyNjEwWjBDMRIwEAYKCZImiZPyLGQBGRYCQ1oxFTATBgNVBAMTDENaMTIxMjEyMTIxODEWMBQGA1UEDRMNZnl6aWNrYSBvc29iYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMecN7X6sgYqq0BOEpdQLZdPZazU/tMcBo1kgoe5GBXW7wRazCBGJtIBJADAqglWZtk75bU24L9buiXgRppclyAUZ1Fzo7tgJ3MOuf1lJSWvN35aJuCRyptxdAEh2RebCF7j/oBxIvEjPWgdb8f2eth8IimY0mq1aiaS/67c/9f0jAq3opp3hMMvEDd0vphJ7Ybk7DV3DCMdyUtOqkcfLFOgQ9q5EwnR7k+wfVvFk6OOwlrsBmvC17ApNYLX2pkmMumc4IORE7NKiws47zTxGRSA4IDu3k94GCTxK69PHsvSwmbQqogUcIdemoqbEAtcMiT60+33d7R5ZHhYjOfcYKMCAwEAAaOCAV4wggFaMAkGA1UdEwQCMAAwHQYDVR0OBBYEFAtC2mlwayQRTB5kWPygTCQ/J6TYMB8GA1UdIwQYMBaAFHwwdqzM1ofR7Mkf4nAILONf3gwHMA4GA1UdDwEB/wQEAwIGwDBjBgNVHSAEXDBaMFgGCmCGSAFlAwIBMAEwSjBIBggrBgEFBQcCAjA8DDpUZW50byBjZXJ0aWZpa8OhdCBieWwgdnlkw6FuIHBvdXplIHBybyB0ZXN0b3ZhY8OtIMO6xI1lbHkuMIGXBgNVHR8EgY8wgYwwgYmggYaggYOGKWh0dHA6Ly9jcmwuY2ExLXBnLmVldC5jei9lZXRjYTFwZy9hbGwuY3JshipodHRwOi8vY3JsMi5jYTEtcGcuZWV0LmN6L2VldGNhMXBnL2FsbC5jcmyGKmh0dHA6Ly9jcmwzLmNhMS1wZy5lZXQuY3ovZWV0Y2ExcGcvYWxsLmNybDANBgkqhkiG9w0BAQsFAAOCAQEAeUeUKL5j8NDzg1PnnC1tPwWOfEUCTCp8d0Ba87Kz1TwBoDlgZZDecm2dkZMlSvXjsu85tibf4XhwxRvsmgc5sLXEUlqbaUB+EqdtamweaRJhCWs2kcnckxm6GeW6vYA6mFn5EJC4+3u4LSA06EEieulnM2ny820nhbyE0/XnWOaTLY1ez6bE5aINjp315o/4zAGATt5rwrbW45UOBGA9vwLM3GzISojt6HoRe7DWNU1KLVSzXbWpT1+HDAXRCg+/UFcD10od9vAJyQ4i0t9yz8/VM3NGatD5W94QFuN1DVVm5m0Uo2kdHuIZEAbmnk9KaIFBg8ModEWGyd5VGdoQaw==",
	},
}

func TestNewCertificate(t *testing.T) {
	for _, cert := range certs {
		t.Run(cert.filepath, func(t *testing.T) {
			raw, err := readFile(t, cert.filepath)
			require.NoError(t, err, "read file")

			p, _ := pem.Decode(raw)
			c, err := wsse.NewCertificate(p)
			require.NoError(t, err, "new certificate")

			require.Equal(t, string(p.Bytes), string(c.Cert().Raw), "DER certificate")
			require.Equal(t, cert.binary, string(c.Binary()), "binary encoded certificate")
		})
	}
}

func readFile(t *testing.T, filepath string) ([]byte, error) {
	t.Helper()

	raw, err := ioutil.ReadFile(filepath)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	return raw, err
}