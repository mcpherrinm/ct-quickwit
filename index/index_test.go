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

var LDAPUri = `
-----BEGIN CERTIFICATE-----
MIIEQDCCA8WgAwIBAgIQVL+Ho8TVCSi+lAovakxOaDAKBggqhkjOPQQDAzBEMQsw
CQYDVQQGEwJERTEVMBMGA1UEChMMRC1UcnVzdCBHbWJIMR4wHAYDVQQDExVELVRS
VVNUIFNTTCBDQSAyIDIwMjAwHhcNMjMxMTEwMTYxNjM2WhcNMjQxMTEzMTYxNjM2
WjAZMRcwFQYDVQQDEw5kZXZzdmMuaXItZC5kZTB2MBAGByqGSM49AgEGBSuBBAAi
A2IABAmCFTxkyFCZOvh2H3WwCAEsReFMq0tAVhPIR1FLyutliFnbcwsBdbc/ZLLp
eQraa+GRlBtirWaS928b4j+pHBDo/ah1xYJfpOVOXv8LxDBYA8JzW2kty2Et0Xfk
e7L6fqOCAqUwggKhMIH9BggrBgEFBQcBAQSB8DCB7TAwBggrBgEFBQcwAYYkaHR0
cDovL3NzbC1jYTItMjAyMC5vY3NwLmQtdHJ1c3QubmV0MEQGCCsGAQUFBzAChjho
dHRwOi8vd3d3LmQtdHJ1c3QubmV0L2NnaS1iaW4vRC1UUlVTVF9TU0xfQ0FfMl8y
MDIwLmNydDBzBggrBgEFBQcwAoZnbGRhcDovL2RpcmVjdG9yeS5kLXRydXN0Lm5l
dC9DTj1ELVRSVVNUJTIwU1NMJTIwQ0ElMjAyJTIwMjAyMCxPPUQtVHJ1c3QlMjBH
bWJILEM9REU/Y0FDZXJ0aWZpY2F0ZT9iYXNlPzB5BgNVHSAEcjBwMAgGBmeBDAEC
ATAIBgYEAI96AQYwWgYLKwYBBAGlNAKBSgMwSzBJBggrBgEFBQcCARY9aHR0cDov
L3d3dy5kLXRydXN0Lm5ldC9pbnRlcm5ldC9maWxlcy9ELVRSVVNUX0NTTV9QS0lf
Q1BTLnBkZjATBgorBgEEAdZ5AgQDAQH/BAIFADCBhAYDVR0fBH0wezB5oHegdYY0
aHR0cDovL2NybC5kLXRydXN0Lm5ldC9jcmwvZC10cnVzdF9zc2xfY2FfMl8yMDIw
LmNybIY9aHR0cDovL2Nkbi5kLXRydXN0LWNsb3VkY3JsLm5ldC9jcmwvZC10cnVz
dF9zc2xfY2FfMl8yMDIwLmNybDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH
AwIwGQYDVR0RBBIwEIIOZGV2c3ZjLmlyLWQuZGUwHwYDVR0jBBgwFoAUuRPycbxr
9Y83k8JMpYfvyksf8TwwDgYDVR0PAQH/BAQDAgOIMB0GA1UdDgQWBBTr19TkZvsR
hlrlDQDV0D54ExivGzAKBggqhkjOPQQDAwNpADBmAjEAr/C3OxMNrNQTXYyGmzqg
gJwt/DcufxZGOMlNp4Hkv9W4m6qeMm8CuesrnPdQ8E7+AjEA8sCUPFuQuz03Dx67
B5Qccd6lAYGbiALpc397by9Cz0/D80ftdk8ereNioQzFDbpH
-----END CERTIFICATE-----
`

var explicitECDSA = `
-----BEGIN CERTIFICATE-----
MIIC1DCCAnmgAwIBAgIUNfzfsIhTfYj5gb9r3w0tV155BlowCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCTkwxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzAyMDExNzU1MDJaFw0yNDAyMDEx
NzU1MDJaMEUxCzAJBgNVBAYTAk5MMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggFLMIIBAwYHKoZIzj0CATCB
9wIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAAAAAAAAAAAAD/////////////
//8wWwQg/////wAAAAEAAAAAAAAAAAAAAAD///////////////wEIFrGNdiqOpPn
s+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLAxUAxJ02CIbnBJNqZnjhE50mt4GffpAE
QQRrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClk/jQuL+Gn+bjufrSnwP
nhYrzjNXazFezsu2QGg3v1H1AiEA/////wAAAAD//////////7zm+q2nF56E87nK
wvxjJVECAQEDQgAEcieVCq4SSMbBoJlBbaIUfNpWD5/5QvZ+We+R0g0fC1qtONH+
XxRejR5yWZ74Am0PGhqTc2Wd15tMNaGKevtrtKNTMFEwHQYDVR0OBBYEFNXN28Uf
IHa+KRChr8mb/GxrEPehMB8GA1UdIwQYMBaAFNXN28UfIHa+KRChr8mb/GxrEPeh
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAPTaymIuOZdIio8O
KdXtKxHt8u92A7Z+94uBqnQVKRUmAiEA2PWv8l/atMTBfx8CamrSwtptWjI44uI3
NpneEJLim74=
-----END CERTIFICATE-----`

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
		{
			name:    "LDAPUri",
			cert:    LDAPUri,
			precert: true,
			want: Document{
				LogURL:    "https://some/logname",
				Index:     123,
				Timestamp: 456,
				Precert:   true,
				SHA256:    "6c331b915df9851189398127ef2ec987b72500eb79c160629af5a0bec374e5ee",
				Certificate: Certificate{
					Version:            2,
					Serial:             "54bf87a3c4d50928be940a2f6a4c4e68",
					SignatureAlgorithm: "1.2.840.10045.4.3.3",
					Issuer:             []TVPair{{Type: "2.5.4.6", Value: "DE"}, {Type: "2.5.4.10", Value: "D-Trust GmbH"}, {Type: "2.5.4.3", Value: "D-TRUST SSL CA 2 2020"}},
					NotBefore:          1699632996,
					NotAfter:           1731514596,
					Subject:            []TVPair{{Type: "2.5.4.3", Value: "devsvc.ir-d.de"}},
					SPKI: SPKI{
						Algorithm: "1.2.840.10045.2.1:2b81040022",
						SHA256:    "5328a41978242a255d81f2e8c6131b3fde8cc55dac4b09c0f052e90bfdf005bd",
					},
					Extensions: []Extension{
						{
							OID: "1.3.6.1.5.5.7.1.1",
							Value: ExtensionAIA{
								AIA: []AccessDescription{
									{
										Method:   "1.3.6.1.5.5.7.48.1",
										Location: map[string]string{"uri": "http://ssl-ca2-2020.ocsp.d-trust.net"},
									},
									{
										Method:   "1.3.6.1.5.5.7.48.2",
										Location: map[string]string{"uri": "http://www.d-trust.net/cgi-bin/D-TRUST_SSL_CA_2_2020.crt"},
									},
									{
										Method:   "1.3.6.1.5.5.7.48.2",
										Location: map[string]string{"uri": "ldap://directory.d-trust.net/CN=D-TRUST%20SSL%20CA%202%202020,O=D-Trust%20GmbH,C=DE?cACertificate?base?"},
									},
								},
							},
						},
						{
							OID: "2.5.29.32",
							Value: []ExtensionCertPolicy{
								{
									Identifier: "2.23.140.1.2.1",
								},
								{
									Identifier: "0.4.0.2042.1.6",
								},
								{
									Identifier: "1.3.6.1.4.1.4788.2.202.3",
									Qualifiers: []TVPair{{Type: "1.3.6.1.5.5.7.2.1", Value: "http://www.d-trust.net/internet/files/D-TRUST_CSM_PKI_CPS.pdf"}},
								},
							},
						},
						{
							OID:      "1.3.6.1.4.1.11129.2.4.3",
							Critical: true,
							Value:    ExtensionPrecertificatePoison{},
						},
						{
							OID: "2.5.29.31",
							Value: ExtensionCRLDP{CRLs: map[string][]string{
								"uri": {"http://crl.d-trust.net/crl/d-trust_ssl_ca_2_2020.crl", "http://cdn.d-trust-cloudcrl.net/crl/d-trust_ssl_ca_2_2020.crl"},
							}},
						},
						{
							OID: "2.5.29.37",
							Value: ExtensionExtKeyUsage{
								ExtendedKeyUsage: []string{"1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"},
							},
						},
						{
							OID: "2.5.29.17",
							Value: ExtensionSAN{
								SubjectAlternativeNames: map[string][]string{"dns": {"devsvc.ir-d.de"}},
							},
						},
						{
							OID: "2.5.29.35",
							Value: ExtensionAKI{
								AuthorityKeyIdentifier: "b913f271bc6bf58f3793c24ca587efca4b1ff13c",
							},
						},
						{
							OID:      "2.5.29.15",
							Critical: true,
							Value: ExtensionKeyUsage{
								KeyUsage: []string{"digital_signature", "key_agreement"},
							},
						},
						{
							OID: "2.5.29.14",
							Value: ExtensionSKI{
								SubjectKeyIdentifier: "ebd7d4e466fb11865ae50d00d5d03e781318af1b",
							},
						},
					},
				},
				Errors: nil,
			},
		},
		{
			name:    "explicitECDSA",
			cert:    explicitECDSA,
			precert: false,
			want: Document{
				LogURL:    "https://some/logname",
				Index:     123,
				Timestamp: 456,
				Precert:   false,
				SHA256:    "a8ffe7b09ab8d8a3eee80c075968dabc0f1b77484efb99627b80a1832455f73d",
				Certificate: Certificate{
					Version:            2,
					Serial:             "35fcdfb088537d88f981bf6bdf0d2d575e79065a",
					SignatureAlgorithm: "1.2.840.10045.4.3.2",
					Issuer:             []TVPair{{Type: "2.5.4.6", Value: "NL"}, {Type: "2.5.4.8", Value: "Some-State"}, {Type: "2.5.4.10", Value: "Internet Widgits Pty Ltd"}},
					NotBefore:          1675274102,
					NotAfter:           1706810102,
					Subject:            []TVPair{{Type: "2.5.4.6", Value: "NL"}, {Type: "2.5.4.8", Value: "Some-State"}, {Type: "2.5.4.10", Value: "Internet Widgits Pty Ltd"}},
					SPKI: SPKI{
						Algorithm: "1.2.840.10045.2.1:020101302c06072a8648ce3d0101022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff305b0420ffffffff00000001000000000000000000000000fffffffffffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b031500c49d360886e704936a6678e1139d26b7819f7e900441046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101",
						SHA256:    "e6eeaecefdab57ac28462daada495e41f60617e8e017593bf721cfc76af8d1f5",
					},
					Extensions: []Extension{
						{
							OID:   "2.5.29.14",
							Value: ExtensionSKI{SubjectKeyIdentifier: "d5cddbc51f2076be2910a1afc99bfc6c6b10f7a1"},
						},
						{
							OID:   "2.5.29.35",
							Value: ExtensionAKI{AuthorityKeyIdentifier: "d5cddbc51f2076be2910a1afc99bfc6c6b10f7a1"},
						},
						{
							OID:      "2.5.29.19",
							Critical: true,
							Value:    ExtensionBasicConstraints{CA: true},
						},
					},
				},
				Errors: nil,
			},
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
