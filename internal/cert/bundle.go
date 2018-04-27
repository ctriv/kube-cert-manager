package cert

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	"github.com/pkg/errors"
	"k8s.io/client-go/pkg/api/unversioned"
	"k8s.io/client-go/pkg/api/v1"
	"liquidweb.com/kube-cert-manager/internal/k8s"
	"liquidweb.com/kube-cert-manager/internal/util"
)

type Bundle struct {
	DomainName  string
	AltNames    []string
	Cert        []byte
	PrivateKey  []byte
	CAExtras    map[string]string
	_ParsedCert *x509.Certificate `json:"-"`
}

func NewBundleFromSecret(s *v1.Secret) (*Bundle, error) {
	var ok bool
	b := new(Bundle)

	b.Cert, ok = s.Data["tls.crt"]
	if !ok {
		return nil, errors.Errorf("Could not find key tls.crt in secret %v", s.Name)
	}

	b.PrivateKey, ok = s.Data["tls.key"]
	if !ok {
		return nil, errors.Errorf("Could not find key tls.key in secret %v", s.Name)
	}

	b.DomainName = b.ParsedCert().Subject.CommonName
	b.AltNames = b.ParsedCert().DNSNames

	return b, nil
}

// ToSecret creates a Kubernetes Secret from an Certificate
func (b *Bundle) ToSecret(name string, labels map[string]string) *v1.Secret {
	var metadata v1.ObjectMeta
	metadata.Name = name

	metadata.Labels = map[string]string{
		"domain":  b.DomainName,
		"creator": "kube-cert-manager",
	}

	for key, value := range labels {
		metadata.Labels[key] = value
	}

	data := make(map[string][]byte)
	data["tls.crt"] = b.Cert
	data["tls.key"] = b.PrivateKey

	return &v1.Secret{
		TypeMeta: unversioned.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		Data:       data,
		ObjectMeta: metadata,
		Type:       "kubernetes.io/tls",
	}
}

func (b *Bundle) ParsedCert() *x509.Certificate {
	if b._ParsedCert != nil {
		return b._ParsedCert
	}

	block, _ := pem.Decode(b.Cert)
	cert, _ := x509.ParseCertificate(block.Bytes)

	b._ParsedCert = cert

	return cert
}

func (b *Bundle) ExpiresDate() time.Time {
	return b.ParsedCert().NotAfter
}

func (b *Bundle) ExpiringWithin(days int) bool {
	return b.ExpiresDate().Before(time.Now().Add(time.Hour * time.Duration(24*days)))
}

func (b *Bundle) SatisfiesCert(cert k8s.Certificate) bool {
	return bytes.Equal(b.Checksum(), cert.Checksum())
}

func (b *Bundle) Checksum() []byte {
	h := sha256.New()

	h.Write([]byte(strings.ToLower(b.DomainName)))

	names := util.NormalizedAltNames(b.AltNames)
	for _, name := range names {
		h.Write([]byte(name))
	}

	return h.Sum(nil)
}
