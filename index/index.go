package index

import (
	"crypto/sha256"
	"encoding/hex"
)

func PrepareDocument(logName string, index int64, der []byte, timestamp uint64, precert bool) (Document, error) {
	var errors []error
	cert, err := ParseCertificate(der)
	if err != nil {
		return Document{}, err
	}

	spkiHash := sha256.New()
	_, err = spkiHash.Write(cert.TBSCertificate.SubjectPublicKeyInfo.Raw)
	if err != nil {
		return Document{}, err
	}

	certHash := sha256.New()
	_, err = certHash.Write(cert.Raw)
	if err != nil {
		return Document{}, err
	}

	extensions, err := Extensions(cert.TBSCertificate.Extensions)
	if err != nil {
		return Document{}, err
	}

	return Document{
		LogURL:    logName,
		Index:     index,
		Timestamp: timestamp,
		Precert:   precert,
		SHA256:    hex.EncodeToString(certHash.Sum(nil)),
		Certificate: Certificate{
			Version:            cert.TBSCertificate.Version,
			Serial:             cert.TBSCertificate.CertificateSerialNumber.Text(16),
			SignatureAlgorithm: cert.TBSCertificate.SignatureAlgorithm.Algorithm.String(), // TODO: algorithm parameters
			Issuer:             PrepareRDNs(cert.TBSCertificate.Issuer),
			NotBefore:          cert.TBSCertificate.Validity.NotBefore.Unix(),
			NotAfter:           cert.TBSCertificate.Validity.NotAfter.Unix(),
			Subject:            PrepareRDNs(cert.TBSCertificate.Subject),
			SPKI: SPKI{
				Algorithm: cert.TBSCertificate.SubjectPublicKeyInfo.Algorithm.Algorithm.String(), // TODO: algorithm parameters
				SHA256:    hex.EncodeToString(spkiHash.Sum(nil)),
			},
			IssuerUniqueID:  hex.EncodeToString(cert.TBSCertificate.IssuerUniqueId.Bytes),
			SubjectUniqueID: hex.EncodeToString(cert.TBSCertificate.SubjectUniqueId.Bytes),
			Extensions:      extensions,
		},
		Errors: errors,
	}, nil
}
