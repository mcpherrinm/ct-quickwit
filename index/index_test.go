package index

import (
	"encoding/pem"
	"reflect"
	"testing"
)

var LEPrecert = `
-----BEGIN CERTIFICATE-----
MIIEHTCCAwWgAwIBAgISA5auPDF3sIwhTigWk6p0gDnNMA0GCSqGSIb3DQEBCwUA
MDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQD
EwNSMTAwHhcNMjQwOTA0MTUwMTM3WhcNMjQxMjAzMTUwMTM2WjArMSkwJwYDVQQD
EyB2YWxpZC1pc3Jncm9vdHgxLmxldHNlbmNyeXB0Lm9yZzCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAKbJuSfDWMs5wm+w2xt5pDAQc4VIvaq0XwCAwvu+
fsVkXB/p9cXQRysuw1EBjDzRGE4UaVvstrznXKNf+hJ+ei33wpCbrCL0y7IrRvaC
IoHrxtb7wlagHBqIE3wgf4g+SlBXw0KR4+23e58A92UqVvFtaCxvze+vFkREVXl1
zoVC8qYswffzcjJrlMXEw0ijTfrxsLuAf9fsF5uJsJLpguDnIqSMtOzhY5pyaUfl
0Bhf8C+OoQA6rp72o1dRiwjnJBNm5WwJAB0QCy6bb3f8sxJDtlGXGXMApcvq5sLt
8+5bxOzpIMBlwmkuG1JiWYRiG52/d1tkQww8YLi6IfaG78cCAwEAAaOCATEwggEt
MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
DAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUIUdj/UGcSUvOYhB8uSv69xNy+2wwHwYD
VR0jBBgwFoAUu7zDR6XkvKnGw6RyDBCNojXhyOgwVwYIKwYBBQUHAQEESzBJMCIG
CCsGAQUFBzABhhZodHRwOi8vcjEwLm8ubGVuY3Iub3JnMCMGCCsGAQUFBzAChhdo
dHRwOi8vcjEwLmkubGVuY3Iub3JnLzArBgNVHREEJDAigiB2YWxpZC1pc3Jncm9v
dHgxLmxldHNlbmNyeXB0Lm9yZzATBgNVHSAEDDAKMAgGBmeBDAECATATBgorBgEE
AdZ5AgQDAQH/BAIFADANBgkqhkiG9w0BAQsFAAOCAQEAXPupE0AYFintlbkBMO4x
PTZydf/pYFbz7DqC17405Ajsqf2BscsRFppkVe7WbFhJFv0T7L2EZs36PO6OliMN
pquiwfD6H9V6bQzCyHhE1e1hAVy4YTrAl366fkraDsMOhR6L12+nr8bGOjDmws6e
+RkCIrQaG7FQtG0WArXqXM1kmAkQqZpciX+Cj2zYyc6rTuT5BKpynKOsI5ee/MGM
J27fCutfIMKsjfG18J00EONFCfr7H5JRRfX78D+yEr6aHnv3rzrV2H9+1KAR5LzK
yeL53dkmUABxGyZEMtI+eJCZNUIUGizTK5913trmCVGTPRlcgwjx/XeMR+Hcpt2z
0A==
-----END CERTIFICATE-----
`

var LEIssuerR10 = []TVPair{
	{Type: "2.5.4.6", Value: "US"},
	{Type: "2.5.4.10", Value: "Let's Encrypt"},
	{Type: "2.5.4.3", Value: "R10"},
}

// TestPrepareDocument provides basic test coverage over certificate parsing
func TestPrepareDocument(t *testing.T) {
	tests := []struct {
		name    string
		cert    string
		precert bool
		want    Document
		wantErr bool
	}{
		{
			name:    "LEPrecert",
			cert:    LEPrecert,
			precert: true,
			want: Document{
				LogURL:    "https://some/logname",
				Index:     123,
				Timestamp: 456,
				Precert:   true,
				SHA256:    "6c445d9b877b253c8fb0a1cefa2da1a5825549c93cf0cc0e6ac324054f9c2e1f",
				Certificate: Certificate{
					Version:            2,
					Serial:             "396ae3c3177b08c214e281693aa748039cd",
					SignatureAlgorithm: "1.2.840.113549.1.1.11",
					Issuer:             LEIssuerR10,
					NotBefore:          1725462097,
					NotAfter:           1733238096,
					Subject:            []TVPair{{Type: "2.5.4.3", Value: "valid-isrgrootx1.letsencrypt.org"}},
					SPKI: SPKI{
						Algorithm: "1.2.840.113549.1.1.1",
						SHA256:    "b1d7c249784a940f6690936de9d6a3ab3041f94b35d22c8633e3265da30d143f",
					},
					Extensions: []Extension{
						{
							OID:      "2.5.29.15",
							Critical: true,
							Value:    ExtensionKeyUsage{KeyUsage: []string{"digital_signature", "key_encipherment"}},
						},
						{
							OID:   "2.5.29.37",
							Value: ExtensionExtKeyUsage{ExtendedKeyUsage: []string{"1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"}},
						},
						{
							OID:      "2.5.29.19",
							Critical: true,
							Value:    ExtensionBasicConstraints{},
						},
						{
							OID:   "2.5.29.14",
							Value: ExtensionSKI{SubjectKeyIdentifier: "214763fd419c494bce62107cb92bfaf71372fb6c"},
						},
						{
							OID:   "2.5.29.35",
							Value: ExtensionAKI{AuthorityKeyIdentifier: "bbbcc347a5e4bca9c6c3a4720c108da235e1c8e8"},
						},
						{
							OID: "1.3.6.1.5.5.7.1.1",
							Value: ExtensionAIA{
								AIA: []AccessDescription{
									{
										Method:   "1.3.6.1.5.5.7.48.1",
										Location: map[string]string{"uri": "http://r10.o.lencr.org"},
									},
									{
										Method:   "1.3.6.1.5.5.7.48.2",
										Location: map[string]string{"uri": "http://r10.i.lencr.org/"},
									},
								},
							},
						},
						{
							OID: "2.5.29.17",
							Value: ExtensionSAN{
								SubjectAlternativeNames: map[string][]string{
									"dns": {"valid-isrgrootx1.letsencrypt.org"},
								},
							},
						},
						{
							OID:   "2.5.29.32",
							Value: []ExtensionCertPolicy{{Identifier: "2.23.140.1.2.1"}},
						},
						{
							OID:      "1.3.6.1.4.1.11129.2.4.3",
							Critical: true,
							Value:    ExtensionPrecertificatePoison{},
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, _ := pem.Decode([]byte(tt.cert))
			got, err := PrepareDocument("https://some/logname", 123, der.Bytes, 456, tt.precert)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrepareDocument() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PrepareDocument() \ngot = %+v\nwant= %+v", got, tt.want)
			}
		})
	}
}
