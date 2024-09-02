package index

import (
	"testing"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

// Test_unpackKeyUsage makes sure the bitmap unpack works right
func Test_unpackKeyUsage(t *testing.T) {
	tests := []struct {
		name string
		ku   x509.KeyUsage
		want []x509.KeyUsage
	}{
		{
			name: "empty",
			ku:   0,
			want: []x509.KeyUsage{},
		},
		{
			name: "sig",
			ku:   x509.KeyUsageDigitalSignature,
			want: []x509.KeyUsage{x509.KeyUsageDigitalSignature},
		},
		{
			name: "all",
			ku:   x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly,
			want: []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageContentCommitment, x509.KeyUsageKeyEncipherment, x509.KeyUsageDataEncipherment, x509.KeyUsageKeyAgreement, x509.KeyUsageCertSign, x509.KeyUsageCRLSign, x509.KeyUsageEncipherOnly, x509.KeyUsageDecipherOnly},
		},
		{
			name: "half",
			ku:   x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCRLSign | x509.KeyUsageDecipherOnly,
			want: []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageKeyEncipherment, x509.KeyUsageKeyAgreement, x509.KeyUsageCRLSign, x509.KeyUsageDecipherOnly},
		},
		{
			name: "other half",
			ku:   x509.KeyUsageContentCommitment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign | x509.KeyUsageEncipherOnly,
			want: []x509.KeyUsage{x509.KeyUsageContentCommitment, x509.KeyUsageDataEncipherment, x509.KeyUsageCertSign, x509.KeyUsageEncipherOnly},
		},
		{
			name: "unknown high value",
			ku:   4097,
			want: []x509.KeyUsage{1, 4096},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unpackKeyUsage(tt.ku)
			if len(got) != len(tt.want) {
				t.Errorf("wrong length: unpackKeyUsage() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("at %d: unpackKeyUsage() = %v, want %v", i, got, tt.want)
				}
			}
		})
	}
}

func TestPrepareOCSPMustStaple(t *testing.T) {
	test := []pkix.Extension{
		{
			Id:       []int{1, 3, 6, 1, 5, 5, 7, 1, 24},
			Critical: false,
			Value:    []byte{0x30, 0x03, 0x02, 0x01, 0x05},
		},
	}
	if !prepareOCSPMustStaple(test) {
		t.Errorf("expected OCSP must staple")
	}
}
