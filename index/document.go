package index

// Document is the JSON indexed in Quickwit
type Document struct {
	LogURL      string      `json:"log_url"`
	Index       int64       `json:"index"`
	Timestamp   uint64      `json:"timestamp"`
	Precert     bool        `json:"precert"`
	SHA256      string      `json:"cert_sha256"`
	Certificate Certificate `json:"cert"`
	Errors      []error     `json:"errors,omitempty"`
}

// Certificate JSON for indexing.
// The structure mostly follows the TBSCertificate format, but simplified
type Certificate struct {
	Version            int                 `json:"version"`
	Serial             string              `json:"serial"`
	SignatureAlgorithm string              `json:"signature_algorithm"`
	Issuer             []DistinguishedName `json:"issuer"`
	NotBefore          int64               `json:"not_before"`
	NotAfter           int64               `json:"not_after"`
	Subject            []DistinguishedName `json:"subject"`
	SPKI               SPKI                `json:"spki"`
	IssuerUniqueID     string              `json:"issuer_unique_id,omitempty"`
	SubjectUniqueID    string              `json:"subject_unique_id,omitempty"`
	Extensions         []Extension         `json:"extensions,omitempty"`
}

type DistinguishedName struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type SPKI struct {
	Algorithm string `json:"algorithm"`
	// We only index a hash of the public key:
	SHA256 string `json:"sha256"`
}

type Extension struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical,omitempty"`
	Unknown  bool   `json:"unknown,omitempty"`
	Value    any    `json:"value"` // The JSON-encodable representation of this extension
}

type AccessDescription struct {
	Method   string            `json:"method"`
	Location map[string]string `json:"location"`
}
type ExtensionAIA struct {
	AIA []AccessDescription `json:"authority_information_access"`
}

type ExtensionAKI struct {
	AuthorityKeyIdentifier string `json:"authority_key_identifier"`
}

type ExtensionSKI struct {
	SubjectKeyIdentifier string `json:"subject_key_identifier"`
}

type ExtensionCertPolicies struct {
	TODOCertPolicies []byte
}

type ExtensionExtKeyUsage struct {
	ExtendedKeyUsage []string
}

type ExtensionSAN struct {
	SubjectAlternativeNames map[string][]string `json:"subject_alternative_names"`
}

type ExtensionNameConstraints struct {
	TODONameConstraints []byte
}

type ExtensionKeyUsage struct {
	KeyUsage []string
}

type ExtensionBasicConstraints struct {
	CA                bool `json:"ca" asn1:"optional"`
	PathLenConstraint *int `json:"path_len_constraint,omitempty" asn1:"optional"`
}

type ExtensionCRLDP struct {
	TODO []byte
}

type ExtensionPrecertificatePoison struct {
	PrecertificatePoison struct{} `json:"precertificate_poison"`
}

type SCT struct {
	Version   int          `json:"version"`
	LogID     string       `json:"log_id"`
	Timestamp uint64       `json:"timestamp"`
	CTIndex   uint64       `json:"ct_index,omitempty"`
	Signature SCTSignature `json:"signature"`
}

// SCTSignature records the algorithms for the hash, but omits the actual signature
type SCTSignature struct {
	Hash string `json:"hash"`
	Algo string `json:"algorithm"`
}

type ExtensionSCTList struct {
	SCTs []SCT `json:"signed_certificate_timestamps"`
}

type ExtensionTLSFeature struct {
	Features []int64 `json:"features"`
}
