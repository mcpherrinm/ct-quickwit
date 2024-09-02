package index

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/google/certificate-transparency-go/x509util"
)

type Document struct {
	LogURL    string   `json:"log_url"`
	Index     int64    `json:"index"`
	Timestamp uint64   `json:"timestamp"`
	Precert   bool     `json:"precert"`
	CertData  CertData `json:"cert_data"`
}

// CertData is what we index out of a certificate
type CertData struct {
	SignatureAlgorithm    string              `json:"signature_algorithm"`
	PublicKeyAlgorithm    string              `json:"public_key_algorithm"`
	Version               int                 `json:"version"`
	SerialNumber          string              `json:"serial_number"`
	Issuer                string              `json:"issuer"`
	Subject               string              `json:"subject"`
	NotBefore             int64               `json:"not_before"`
	NotAfter              int64               `json:"not_after"`
	KeyUsage              []string            `json:"key_usage"`
	ExtKeyUsage           []string            `json:"ext_key_usage"`
	SubjectKeyID          string              `json:"subject_key_id"`
	AuthorityKeyID        string              `json:"authority_key_id"`
	OCSPServer            []string            `json:"ocsp_server,omitempty"`
	IssuingCertificateURL []string            `json:"issuing_certificate_url,omitempty"`
	CRLDistributionPoints []string            `json:"crl_distribution_points,omitempty"`
	DNSNames              []string            `json:"dns_names,omitempty"`
	IPAddresses           []net.IP            `json:"ip_addresses,omitempty"`
	SPKIHash              string              `json:"spki_hash"`
	CertFingerprint       string              `json:"cert_fingerprint"`
	SCTs                  []SCTData           `json:"scts,omitempty"`
	PolicyIdentifiers     []string            `json:"policy_identifiers,omitempty"`
	NameConstraintData    *NameConstraintData `json:"name_constraints,omitempty"`
	Extensions            []string            `json:"extensions,omitempty"`
	OCSPMustStaple        bool                `json:"ocsp_must_staple,omitempty"`

	// IsCA, MaxPathLen, MaxPathLenZero - seems messy, can we do better here?

	// ZLint lints?
}

// SCTData is what we index out of an SCT
type SCTData struct {
	SCTVersion         uint64 `json:"sct_version"`
	LogID              string `json:"log_id"`
	Timestamp          uint64 `json:"timestamp"`
	LeafIndex          int64  `json:"leaf_index,omitempty"`
	HashAlgorithm      string `json:"hash_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
}

type NameConstraintData struct {
	Critical                bool         `json:"critical,omitempty"`
	PermittedDNSDomains     []string     `json:"permitted_dns_domains,omitempty"`
	ExcludedDNSDomains      []string     `json:"excluded_dns_domains,omitempty"`
	PermittedIPRanges       []*net.IPNet `json:"permitted_ip_ranges,omitempty"`
	ExcludedIPRanges        []*net.IPNet `json:"excluded_ip_ranges,omitempty"`
	PermittedEmailAddresses []string     `json:"permitted_email_addresses,omitempty"`
	ExcludedEmailAddresses  []string     `json:"excluded_email_addresses,omitempty"`
	PermittedURIDomains     []string     `json:"permitted_uri_domains,omitempty"`
	ExcludedURIDomains      []string     `json:"excluded_uri_domains,omitempty"`
}

func Index(url, pemPK string, start, end int64, continuous bool, entriesChan chan Document) error {
	derPK, err := base64.StdEncoding.DecodeString(pemPK)
	if err != nil {
		return err
	}

	ctclient, err := client.New(url, http.DefaultClient, jsonclient.Options{
		PublicKeyDER: derPK,
		UserAgent:    "ct-quickwit-indexer/0.2",
	})
	if err != nil {
		return err
	}

	scr := scanner.NewScanner(ctclient, scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     256,
			ParallelFetch: 1,
			StartIndex:    start,
			EndIndex:      end,
			Continuous:    continuous,
		},
		Matcher:     scanner.MatchAll{},
		PrecertOnly: false,
		NumWorkers:  1,
		BufferSize:  0,
	})

	err = scr.Scan(context.Background(), func(cert *ct.RawLogEntry) {
		entry, err := prepareDocument(url, cert, false)
		if err != nil {
			log.Printf("Failed to prepare document: %v", err)
		}
		entriesChan <- entry
	}, func(precert *ct.RawLogEntry) {
		entry, err := prepareDocument(url, precert, true)
		if err != nil {
			log.Printf("Failed to prepare document: %v", err)
		}
		entriesChan <- entry
	})
	if err != nil {
		return err
	}

	close(entriesChan)

	return nil
}

func prepareDocument(logName string, entry *ct.RawLogEntry, precert bool) (Document, error) {
	parsed, err := x509.ParseCertificates(entry.Cert.Data)
	if err != nil {
		return Document{}, err
	}

	if len(parsed) == 0 {
		return Document{}, fmt.Errorf("No leaf certificate found at index %d", entry.Index)
	}
	cert := parsed[0]

	spkiHash := sha256.New()
	_, err = spkiHash.Write(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return Document{}, err
	}

	certHash := sha256.New()
	_, err = certHash.Write(cert.Raw)
	if err != nil {
		return Document{}, err
	}

	SCTs, err := prepareSCTs(&cert.SCTList)
	if err != nil {
		// Log but tolerate SCTs we can't parse. Shouldn't happen.
		log.Printf("Failed to parse SCTs: %v", err)
	}

	return Document{
		LogURL:    logName,
		Index:     entry.Index,
		Timestamp: entry.Leaf.TimestampedEntry.Timestamp,
		Precert:   precert,
		CertData: CertData{
			SignatureAlgorithm:    cert.SignatureAlgorithm.String(),
			PublicKeyAlgorithm:    cert.PublicKeyAlgorithm.String(),
			Version:               cert.Version,
			SerialNumber:          cert.SerialNumber.Text(16),
			Issuer:                cert.Issuer.ToRDNSequence().String(),
			Subject:               cert.Subject.ToRDNSequence().String(),
			NotBefore:             cert.NotBefore.Unix(),
			NotAfter:              cert.NotAfter.Unix(),
			DNSNames:              cert.DNSNames,
			IPAddresses:           cert.IPAddresses,
			KeyUsage:              prepareKeyUsage(cert.KeyUsage),
			ExtKeyUsage:           prepareEKU(cert.ExtKeyUsage, cert.UnknownExtKeyUsage),
			SubjectKeyID:          hex.EncodeToString(cert.SubjectKeyId),
			AuthorityKeyID:        hex.EncodeToString(cert.AuthorityKeyId),
			OCSPServer:            cert.OCSPServer,
			IssuingCertificateURL: cert.IssuingCertificateURL,
			CRLDistributionPoints: cert.CRLDistributionPoints,
			SPKIHash:              hex.EncodeToString(spkiHash.Sum(nil)),
			CertFingerprint:       hex.EncodeToString(certHash.Sum(nil)),
			SCTs:                  SCTs,
			PolicyIdentifiers:     preparePolicies(cert.PolicyIdentifiers),
			NameConstraintData:    prepareNameConstraints(cert),
			Extensions:            prepareExtensions(cert.Extensions),
			OCSPMustStaple:        prepareOCSPMustStaple(cert.Extensions),
		},
	}, nil
}

func unpackKeyUsage(keyUsageBitmap x509.KeyUsage) []x509.KeyUsage {
	var keyUsageList []x509.KeyUsage
	for shifted := 0; keyUsageBitmap != 0; shifted++ {
		// if the low bit is current set, then 1 << shifted was set originally
		if keyUsageBitmap&1 == 1 {
			keyUsageList = append(keyUsageList, 1<<shifted)
		}
		keyUsageBitmap = keyUsageBitmap >> 1
	}
	return keyUsageList
}

var kuNames = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "digital_signature",
	x509.KeyUsageContentCommitment: "content_commitment",
	x509.KeyUsageKeyEncipherment:   "key_encipherment",
	x509.KeyUsageDataEncipherment:  "data_encipherment",
	x509.KeyUsageKeyAgreement:      "key_agreement",
	x509.KeyUsageCertSign:          "cert_sign",
	x509.KeyUsageCRLSign:           "crl_sign",
	x509.KeyUsageEncipherOnly:      "encipher_only",
	x509.KeyUsageDecipherOnly:      "decipher_only",
}

func prepareKeyUsage(usageBitmap x509.KeyUsage) []string {
	var keyUsageList []string
	for _, ku := range unpackKeyUsage(usageBitmap) {
		name, ok := kuNames[ku]
		if !ok {
			keyUsageList = append(keyUsageList, fmt.Sprintf("Unknown key usage: %v", ku))
		} else {
			keyUsageList = append(keyUsageList, name)
		}
	}
	return keyUsageList
}

var ekuNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "any",
	x509.ExtKeyUsageServerAuth:                     "server_auth",
	x509.ExtKeyUsageClientAuth:                     "client_auth",
	x509.ExtKeyUsageCodeSigning:                    "code_signing",
	x509.ExtKeyUsageEmailProtection:                "email_protection",
	x509.ExtKeyUsageIPSECEndSystem:                 "ipsec_end_system",
	x509.ExtKeyUsageIPSECTunnel:                    "ipsec_tunnel",
	x509.ExtKeyUsageIPSECUser:                      "ipsec_user",
	x509.ExtKeyUsageTimeStamping:                   "time_stamping",
	x509.ExtKeyUsageOCSPSigning:                    "ocsp_signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "microsoft_server_gated_crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "netscape_server_gated_crypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "microsoft_commercial_code_signing",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "microsoft_kernel_code_signing",
	x509.ExtKeyUsageCertificateTransparency:        "certificate_transparency",
}

// prepareEKU turns the internal Go identifiers into strings
func prepareEKU(ekus []x509.ExtKeyUsage, unknownEKUs []asn1.ObjectIdentifier) []string {
	ret := make([]string, 0, len(ekus)+len(unknownEKUs))
	for _, eku := range ekus {
		name, ok := ekuNames[eku]
		if !ok {
			ret = append(ret, fmt.Sprintf("Unknown EKU: %v", eku))
		} else {
			ret = append(ret, name)
		}
	}

	for _, unknownEKU := range unknownEKUs {
		ret = append(ret, unknownEKU.String())
	}

	return ret
}

func prepareSCTs(list *x509.SignedCertificateTimestampList) ([]SCTData, error) {
	parsed, err := x509util.ParseSCTsFromSCTList(list)
	if err != nil {
		return nil, err
	}

	data := make([]SCTData, 0, len(parsed))
	for _, sct := range parsed {
		// TODO: parse the extensions for Static CT API LeafIndex

		data = append(data, SCTData{
			SCTVersion:         uint64(sct.SCTVersion),
			LogID:              hex.EncodeToString(sct.LogID.KeyID[:]),
			Timestamp:          sct.Timestamp,
			LeafIndex:          0,
			HashAlgorithm:      sct.Signature.Algorithm.Hash.String(),
			SignatureAlgorithm: sct.Signature.Algorithm.Signature.String(),
		})
	}

	return data, nil
}

func preparePolicies(l []asn1.ObjectIdentifier) []string {
	var ret []string
	for _, oid := range l {
		ret = append(ret, oidString(oid))
	}
	return ret
}

var EV asn1.ObjectIdentifier = []int{2, 23, 140, 1, 1}
var DV asn1.ObjectIdentifier = []int{2, 23, 140, 1, 2, 1}
var OV asn1.ObjectIdentifier = []int{2, 23, 140, 1, 2, 2}
var IV asn1.ObjectIdentifier = []int{2, 23, 140, 1, 2, 3}
var SE asn1.ObjectIdentifier = []int{1, 3, 6, 1, 4, 1, 11129, 2, 1, 22}
var SCTPoison asn1.ObjectIdentifier = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
var CRLDP asn1.ObjectIdentifier = []int{2, 5, 29, 31}
var SANs asn1.ObjectIdentifier = []int{2, 5, 29, 17}
var AIA asn1.ObjectIdentifier = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
var SKI asn1.ObjectIdentifier = []int{2, 5, 29, 14}
var keyUsage asn1.ObjectIdentifier = []int{2, 5, 29, 15}
var basicConstraints asn1.ObjectIdentifier = []int{2, 5, 29, 19}
var certificatePolicies asn1.ObjectIdentifier = []int{2, 5, 29, 32}
var AKI asn1.ObjectIdentifier = []int{2, 5, 29, 35}
var extendedKeyUsage asn1.ObjectIdentifier = []int{2, 5, 29, 37}
var tlsFeature asn1.ObjectIdentifier = []int{1, 3, 6, 1, 5, 5, 7, 1, 24}
var SCT asn1.ObjectIdentifier = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

func oidString(oid asn1.ObjectIdentifier) string {
	if oid.Equal(EV) {
		return "extended-validation"
	}
	if oid.Equal(DV) {
		return "domain-validated"
	}
	if oid.Equal(OV) {
		return "organization-validated"
	}
	if oid.Equal(IV) {
		return "individual-validated"
	}
	if oid.Equal(SE) {
		return "can-sign-http-exchanges"
	}
	if oid.Equal(SCTPoison) {
		return "sct-poison"
	}
	if oid.Equal(CRLDP) {
		return "crl-distribution-point"
	}
	if oid.Equal(SANs) {
		return "subject-alternative-names"
	}
	if oid.Equal(AIA) {
		return "authority-info-access"
	}
	if oid.Equal(SKI) {
		return "subject-key-identifier"
	}
	if oid.Equal(keyUsage) {
		return "key-usage"
	}
	if oid.Equal(basicConstraints) {
		return "basic-constraints"
	}
	if oid.Equal(certificatePolicies) {
		return "certificate-policies"
	}
	if oid.Equal(AKI) {
		return "authority-key-identifier"
	}
	if oid.Equal(extendedKeyUsage) {
		return "extended-key-usage"
	}
	if oid.Equal(tlsFeature) {
		return "tls-feature"
	}
	if oid.Equal(SCT) {
		return "signed-certificate-timestamps"
	}
	return oid.String()
}

// prepareNameConstraints returns non-null NameConstraintData if anything is set
func prepareNameConstraints(cert *x509.Certificate) *NameConstraintData {
	if cert.PermittedDNSDomainsCritical == true ||
		len(cert.PermittedDNSDomains) != 0 ||
		len(cert.ExcludedDNSDomains) != 0 ||
		len(cert.PermittedIPRanges) != 0 ||
		len(cert.ExcludedIPRanges) != 0 ||
		len(cert.PermittedEmailAddresses) != 0 ||
		len(cert.ExcludedEmailAddresses) != 0 ||
		len(cert.PermittedURIDomains) != 0 ||
		len(cert.ExcludedURIDomains) != 0 {
		return &NameConstraintData{
			Critical:                cert.PermittedDNSDomainsCritical,
			PermittedDNSDomains:     cert.PermittedDNSDomains,
			ExcludedDNSDomains:      cert.ExcludedDNSDomains,
			PermittedIPRanges:       cert.PermittedIPRanges,
			ExcludedIPRanges:        cert.ExcludedIPRanges,
			PermittedEmailAddresses: cert.PermittedEmailAddresses,
			ExcludedEmailAddresses:  cert.ExcludedEmailAddresses,
			PermittedURIDomains:     cert.PermittedURIDomains,
			ExcludedURIDomains:      cert.ExcludedURIDomains,
		}
	}
	return nil
}

// prepareExtensions returns a list of strings with the OIDs and critical bit of certificate extensions
func prepareExtensions(exts []pkix.Extension) []string {
	var ret []string
	for _, ext := range exts {
		v := oidString(ext.Id)
		if ext.Critical {
			v += ":critical"
		}
		ret = append(ret, v)
	}
	return ret
}

// prepareOCSPMustStaple looks for an OCSP Must Staple extension
func prepareOCSPMustStaple(exts []pkix.Extension) bool {
	for _, ext := range exts {
		if ext.Id.Equal(tlsFeature) {
			// The TLS Feature extension has an ASN.1 SEQUENCE of INTEGER
			var features []int64
			rest, err := asn1.Unmarshal(ext.Value, &features)
			if err != nil {
				log.Printf("Error unmarshalling TLS Feature extension: %v", err)
				return false
			}
			if len(rest) != 0 {
				log.Printf("Extra %d bytes after TLS Feature extension", len(rest))
			}
			for _, feature := range features {
				// status_request
				if feature == 5 {
					return true
				}
				// status_request_v2 - Unused?
				if feature == 17 {
					return true
				}
			}
			log.Printf("Found a TLS-Feature extension that wasn't must-staple? %v", ext.Value)
		}
	}
	return false
}
