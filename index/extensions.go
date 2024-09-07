package index

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"

	"github.com/google/certificate-transparency-go/tls"
)

// Extensions returns a list of strings with the OIDs and critical bit of certificate extensions
func Extensions(exts []pkix.Extension) ([]Extension, error) {
	var ret []Extension
	for _, ext := range exts {
		unknown := false
		oid := ext.Id.String()
		v, err := parseExtension(oid, ext.Value)
		if err != nil {
			// TODO: ideally just this extension would get an error and we'd parse the rest
			return nil, err
		}
		if v == nil {
			// Unknown extension, flag and index the bytes.
			unknown = true
			v = ext.Value
		}
		ret = append(ret, Extension{
			OID:      oid,
			Critical: ext.Critical,
			Value:    v,
			Unknown:  unknown,
		})
	}
	return ret, nil
}

// parseExtension hands off to a per-extension function based on OID
// The return value is intended to be JSON-encoded
// Unknown extensions return nil
func parseExtension(oid string, value []byte) (any, error) {
	switch oid {
	case "1.3.6.1.5.5.7.1.1":
		return parseAIA(value)
	case "2.5.29.35":
		return parseAKI(value)
	case "2.5.29.14":
		return parseSKI(value)
	case "2.5.29.32":
		return parseCertPolicies(value)
	case "2.5.29.37":
		return parseExtKeyUsage(value)
	case "2.5.29.17":
		return parseSAN(value)
	case "2.5.29.30":
		return parseNameConstraints(value)
	case "2.5.29.15":
		return parseKeyUsage(value)
	case "2.5.29.19":
		return parseBasicConstraints(value)
	case "2.5.29.31":
		return parseCRLDP(value)
	case "1.3.6.1.4.1.11129.2.4.2":
		return parseSCTExtension(value)
	case "1.3.6.1.4.1.11129.2.4.3":
		return parsePrecertificatePoison(value)
	case "1.3.6.1.5.5.7.1.24":
		return parseTLSFeature(value)
	}
	return nil, nil
}

func unmarshalASN1[T any](data []byte) (T, error) {
	var ret T
	rest, err := asn1.Unmarshal(data, &ret)
	if err != nil {
		return ret, err
	}
	if len(rest) != 0 {
		return ret, fmt.Errorf("trailing data: %d bytes", len(rest))
	}
	return ret, nil
}

func parseAIA(data []byte) (ExtensionAIA, error) {
	raw, err := unmarshalASN1[[]ASN1AccessDescription](data)
	if err != nil {
		return ExtensionAIA{}, err
	}

	var ret []AccessDescription
	for _, entry := range raw {
		tag, val := GeneralName(entry.AccessLocation)
		ad := AccessDescription{
			Method:   entry.AccessMethod.String(),
			Location: map[string]string{tag: val},
		}
		ret = append(ret, ad)
	}
	return ExtensionAIA{AIA: ret}, nil
}

func parseAKI(data []byte) (ExtensionAKI, error) {
	aki, err := unmarshalASN1[ASN1AuthorityKeyIdentifier](data)
	if err != nil {
		return ExtensionAKI{}, err
	}

	return ExtensionAKI{
		AuthorityKeyIdentifier: hex.EncodeToString(aki.Id),
	}, nil
}

func parseSKI(data []byte) (ExtensionSKI, error) {
	ski, err := unmarshalASN1[[]byte](data)
	if err != nil {
		return ExtensionSKI{}, err
	}
	return ExtensionSKI{
		SubjectKeyIdentifier: hex.EncodeToString(ski),
	}, nil
}

func parseCertPolicies(data []byte) ([]ExtensionCertPolicy, error) {
	policies, err := unmarshalASN1[[]ASN1PolicyInformation](data)
	if err != nil {
		return nil, err
	}

	var ret []ExtensionCertPolicy

	for _, policy := range policies {
		ret = append(ret, ExtensionCertPolicy{
			Identifier: policy.PolicyIdentifier.String(),
			Qualifiers: parsePolicyQualifiers(policy.PolicyQualifiers),
		})
	}

	return ret, nil
}

func parsePolicyQualifiers(qualifiers []ASN1PolicyQualifierInfo) []TVPair {
	var ret []TVPair
	for _, qualifier := range qualifiers {
		oid := qualifier.PolicyQualifierID.String()
		var value string

		if oid == "1.3.6.1.5.5.7.2.1" { // CPS URI
			value = string(qualifier.Qualifier.Bytes)
		} else {
			value = hex.EncodeToString(qualifier.Qualifier.Bytes)
		}

		ret = append(ret, TVPair{Type: oid, Value: value})
	}
	return ret
}

func parseExtKeyUsage(data []byte) (ExtensionExtKeyUsage, error) {
	ekus, err := unmarshalASN1[[]asn1.ObjectIdentifier](data)
	if err != nil {
		return ExtensionExtKeyUsage{}, err
	}

	var ekustrings []string
	for _, eku := range ekus {
		ekustrings = append(ekustrings, eku.String())
	}

	return ExtensionExtKeyUsage{
		ExtendedKeyUsage: ekustrings,
	}, nil
}

func parseSAN(data []byte) (ExtensionSAN, error) {
	rawSANs, err := unmarshalASN1[[]asn1.RawValue](data)
	if err != nil {
		return ExtensionSAN{}, err
	}

	sans := make(map[string][]string)

	for _, san := range rawSANs {
		tag, val := GeneralName(san)
		sans[tag] = append(sans[tag], val)
	}

	return ExtensionSAN{SubjectAlternativeNames: sans}, nil
}

func parseNameConstraints(data []byte) (ExtensionNameConstraints, error) {
	return ExtensionNameConstraints{
		TODONameConstraints: data,
	}, nil
}

func parseKeyUsage(data []byte) (ExtensionKeyUsage, error) {
	keyUsageBitmask, err := unmarshalASN1[asn1.BitString](data)
	if err != nil {
		return ExtensionKeyUsage{}, err
	}

	var usage []string

	// The order of these strings matches their index to the bit in the bitmap
	for index, name := range []string{
		"digital_signature",
		"content_commitment",
		"key_encipherment",
		"data_encipherment",
		"key_agreement",
		"key_cert_sign",
		"crl_sign",
		"encipher_only",
		"decipher_only",
	} {
		if keyUsageBitmask.At(index) != 0 {
			usage = append(usage, name)
		}
	}

	return ExtensionKeyUsage{
		KeyUsage: usage,
	}, nil
}

func parseBasicConstraints(data []byte) (ExtensionBasicConstraints, error) {
	return unmarshalASN1[ExtensionBasicConstraints](data)
}

func parseCRLDP(data []byte) (ExtensionCRLDP, error) {
	crldps, err := unmarshalASN1[[]ASN1DistributionPoint](data)
	if err != nil {
		return ExtensionCRLDP{}, err
	}

	crlmap := make(map[string][]string)

	for _, crldp := range crldps {
		for _, name := range crldp.DistributionPoint.FullName {
			tag, val := GeneralName(name)
			crlmap[tag] = append(crlmap[tag], val)
		}
	}

	return ExtensionCRLDP{CRLs: crlmap}, nil
}

func parsePrecertificatePoison(data []byte) (ExtensionPrecertificatePoison, error) {
	// This extension MUST have an extnValue OCTET STRING which is exactly the hex‐encoded bytes
	// 0500, the encoded representation of the ASN.1 NULL value, as specified in RFC 6962, Section 3.1.
	if len(data) != 2 || data[0] != 0x05 || data[1] != 0x00 {
		return ExtensionPrecertificatePoison{}, fmt.Errorf("invalid precertificate poison")
	}
	return ExtensionPrecertificatePoison{PrecertificatePoison: struct{}{}}, nil
}

func parseSCTExtension(data []byte) (ExtensionSCTList, error) {
	// The SCT Extension value is an OCTET STRING, which is a TLS-encoded list of SCTs
	tlsList, err := unmarshalASN1[[]byte](data)
	if err != nil {
		return ExtensionSCTList{}, err
	}

	var list TLSSctList
	rest, err := tls.Unmarshal(tlsList, &list)
	if err != nil {
		return ExtensionSCTList{}, fmt.Errorf("unmarshalling sct list: %w", err)
	}
	if len(rest) != 0 {
		return ExtensionSCTList{}, fmt.Errorf("trailing TLS data: %d bytes", len(rest))
	}

	var SCTs []SCT
	for _, entry := range list.List {
		var sct TLSSCT
		rest, err := tls.Unmarshal(entry.Data, &sct)
		if err != nil {
			return ExtensionSCTList{}, fmt.Errorf("error unmarshaling sct: %w", err)
		}
		if len(rest) != 0 {
			return ExtensionSCTList{}, fmt.Errorf("trailing data: %d bytes", len(rest))
		}
		SCTs = append(SCTs, SCT{
			Version:   int(sct.SCTVersion),
			LogID:     hex.EncodeToString(sct.LogID[:]),
			Timestamp: sct.Timestamp,
			Signature: SCTSignature{
				Hash: sct.Signature.Algorithm.Hash.String(),
				Algo: sct.Signature.Algorithm.Signature.String(),
			},
		})
	}

	return ExtensionSCTList{SCTs: SCTs}, nil
}

func parseTLSFeature(data []byte) (ExtensionTLSFeature, error) {
	features, err := unmarshalASN1[[]int64](data)
	if err != nil {
		return ExtensionTLSFeature{}, err
	}
	return ExtensionTLSFeature{Features: features}, nil
}
