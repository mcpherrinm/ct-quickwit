package index

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
)

func ParseCertificate(der []byte) (ASN1Certificate, error) {
	var cert ASN1Certificate
	rest, err := asn1.Unmarshal(der, &cert)
	if err != nil {
		return ASN1Certificate{}, err
	}
	if len(rest) != 0 {
		return ASN1Certificate{}, fmt.Errorf("%d trailing bytes after certificate", len(rest))
	}

	return cert, nil
}

// GeneralName returns the type and value as strings
//
//	GeneralName ::= CHOICE {
//	  otherName                       [0]     OtherName,
//	  rfc822Name                      [1]     IA5String,
//	  dNSName                         [2]     IA5String,
//	  x400Address                     [3]     ORAddress,
//	  directoryName                   [4]     Name,
//	  ediPartyName                    [5]     EDIPartyName,
//	  uniformResourceIdentifier       [6]     IA5String,
//	  iPAddress                       [7]     OCTET STRING,
//	  registeredID                    [8]     OBJECT IDENTIFIER
//	}
func GeneralName(v asn1.RawValue) (string, string) {
	// general unsupported version is just the tag and hex:
	tag := fmt.Sprintf("general_name:%d", v.Tag)
	val := hex.EncodeToString(v.Bytes)

	switch v.Tag {
	case 1:
		tag = "rfc822"
		val = string(v.Bytes)
	case 2:
		tag = "dns"
		val = string(v.Bytes)
	case 6:
		tag = "uri"
		val = string(v.Bytes)
	case 7:
		tag = "ip_address"
		val = net.IP(v.Bytes).String()
	}
	return tag, val
}

// PrepareRDNs turns a pkix.RDNSequence into
func PrepareRDNs(seq pkix.RDNSequence) []TVPair {
	var ret []TVPair
	for _, set := range seq {
		for _, dn := range set {
			value, ok := dn.Value.(string)
			if !ok {
				// TODO: The value wasn't string-ey
				value = "<unknown>"
			}
			ret = append(ret, TVPair{
				Type:  dn.Type.String(),
				Value: value,
			})
		}
	}
	return ret
}

func PrepareAlgo(algo pkix.AlgorithmIdentifier) string {
	if len(algo.Parameters.Bytes) != 0 {
		// TODO: Better representation here
		return algo.Algorithm.String() + ":" + hex.EncodeToString(algo.Parameters.Bytes)
	}
	return algo.Algorithm.String()
}
