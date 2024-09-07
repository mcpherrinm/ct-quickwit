package index

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"

	"github.com/google/certificate-transparency-go/tls"
)

//	Certificate  ::=  SEQUENCE  {
//	  tbsCertificate       TBSCertificate,
//	  signatureAlgorithm   AlgorithmIdentifier,
//	  signatureValue       BIT STRING  }
type ASN1Certificate struct {
	Raw asn1.RawContent

	TBSCertificate     ASN1TBSCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

//	TBSCertificate  ::=  SEQUENCE  {
//	  version         [0]  EXPLICIT Version DEFAULT v1,
//	  serialNumber         CertificateSerialNumber,
//	  signature            AlgorithmIdentifier,
//	  issuer               Name,
//	  validity             Validity,
//	  subject              Name,
//	  subjectPublicKeyInfo SubjectPublicKeyInfo,
//	  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//	                       -- If present, version MUST be v2 or v3
//	  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//	                       -- If present, version MUST be v2 or v3
//	  extensions      [3]  EXPLICIT Extensions OPTIONAL
//	                       -- If present, version MUST be v3 }
type ASN1TBSCertificate struct {
	Raw asn1.RawContent

	Version                 int `asn1:"optional,explicit,default:0,tag:0"`
	CertificateSerialNumber *big.Int
	SignatureAlgorithm      pkix.AlgorithmIdentifier
	Issuer                  pkix.RDNSequence
	Validity                ASN1Validity
	Subject                 pkix.RDNSequence
	SubjectPublicKeyInfo    ASN1SubjectPublicKeyInfo
	IssuerUniqueId          asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId         asn1.BitString   `asn1:"optional,tag:2"`
	Extensions              []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

//	Validity ::= SEQUENCE {
//	  notBefore      Time,
//	  notAfter       Time }
type ASN1Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

//	SubjectPublicKeyInfo  ::=  SEQUENCE  {
//	  algorithm            AlgorithmIdentifier,
//	  subjectPublicKey     BIT STRING  }
type ASN1SubjectPublicKeyInfo struct {
	Raw asn1.RawContent

	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

//		AccessDescription  ::=  SEQUENCE {
//	   accessMethod          OBJECT IDENTIFIER,
//	   accessLocation        GeneralName  }
type ASN1AccessDescription struct {
	AccessMethod   asn1.ObjectIdentifier
	AccessLocation asn1.RawValue
}

type TLSSctList struct {
	List []TLSSCTRaw `tls:"minlen:1,maxlen:65535"`
}

type TLSSCTRaw struct {
	Data []byte `tls:"minlen:1,maxlen:65535"`
}

type TLSSCT struct {
	SCTVersion tls.Enum `tls:"maxval:255"`
	LogID      [sha256.Size]byte
	Timestamp  uint64
	Extensions []byte `tls:"minlen:0,maxlen:65535"` // TODO: Use ct-static-api definition
	Signature  tls.DigitallySigned
}

// ASN1AuthorityKeyIdentifier has a few options, but we only support KeyIdentifier
//
//	AuthorityKeyIdentifier ::= SEQUENCE {
//	  keyIdentifier             [0] KeyIdentifier           OPTIONAL,
//	  authorityCertIssuer       [1] GeneralNames            OPTIONAL,
//	  authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
//
// KeyIdentifier ::= OCTET STRING
type ASN1AuthorityKeyIdentifier struct {
	Id []byte `asn1:"optional,tag:0"`
}

type ASN1DistributionPoint struct {
	DistributionPoint ASN1DistributionPointName `asn1:"optional,tag:0"`
}

type ASN1DistributionPointName struct {
	FullName []asn1.RawValue `asn1:"optional,tag:0"`
}
