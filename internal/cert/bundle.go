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

// Bundle is a representation of what we commmonly think of when we think of a
// TLS cert.  It contains the cert and private key, along with metadata such as
// the the domain name, alternate names, and any extra data the CA needs.
type Bundle struct {
	DomainName string
	AltNames   []string
	Cert       []byte
	PrivateKey []byte
	CAExtras   map[string]string
	parsedCert *x509.Certificate
}

// NewBundleFromSecret takes a kubernetes secret struct and returns a Bundle with
// containing the same logical data.
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

// ParsedCert returns a x509 Certificate struct.  This is useful for pulling
// metadata out the cert, such as the subject or expiration date.
func (b *Bundle) ParsedCert() *x509.Certificate {
	if b.parsedCert != nil {
		return b.parsedCert
	}

	block, _ := pem.Decode(b.Cert)
	cert, _ := x509.ParseCertificate(block.Bytes)

	b.parsedCert = cert

	return cert
}

// ExpiresDate returns the datetime that this cert will expire as a time.Time
func (b *Bundle) ExpiresDate() time.Time {
	return b.ParsedCert().NotAfter
}

// ExpiringWithin tells you if a cert is expiring before a certain numbers of
// days.  Takes a day count as an int and returns a bool.
//
// For example, if you wanted to know if a cert is expiring within the next 30
// days:
//        if cert.ExpiringWithin(30) {
//            Renew(Cert)
//        }
func (b *Bundle) ExpiringWithin(days int) bool {
	return b.ExpiresDate().Before(time.Now().Add(time.Hour * time.Duration(24*days)))
}

// SatisfiesCert takes a k8s.Certificate struct and returns true if the cert
// bundle conforms the specification in the k8s.Certificate struct. False otherwise.
func (b *Bundle) SatisfiesCert(cert k8s.Certificate) bool {
	return bytes.Equal(b.Checksum(), cert.Checksum())
}

// Checksum returns a byte slice containing a hash that represents the uniquely
// identifying data within the bundle.
func (b *Bundle) Checksum() []byte {
	h := sha256.New()

	h.Write([]byte(strings.ToLower(b.DomainName)))

	names := util.NormalizedAltNames(b.AltNames)
	for _, name := range names {
		h.Write([]byte(name))
	}

	return h.Sum(nil)
}
