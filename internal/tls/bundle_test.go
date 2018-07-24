package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"testing"
	"time"

	"github.com/liquidweb/kube-cert-manager/internal/k8s"
	"k8s.io/client-go/pkg/api/v1"
)

func TestNewBundleBadInputs(t *testing.T) {
	// lets test some bad inputs
	inputTests := []struct {
		cert []byte
		key  []byte
		desc string
	}{
		{
			cert: []byte{},
			key:  []byte{},
			desc: "empty inputs",
		},
		{
			cert: []byte("epcot"),
			key:  []byte{},
			desc: "not PEM",
		},
		{
			cert: []byte(`-----BEGIN CERTIFICATE-----
X1YsQzP1KKQ=
-----END CERTIFICATE-----`),
			key:  []byte{},
			desc: "invalid cert",
		},
	}

	for _, in := range inputTests {
		b, err := NewBundle(in.cert, in.key)
		if b != nil {
			t.Errorf("Got bundle back for %s", in.desc)
		}
		if err == nil {
			t.Errorf("Didn't get an error back for %s", in.desc)
		}
	}
}

func TestNewBundleValidCert(t *testing.T) {
	cert, key := getSelfSignedCert("epcot.org", 15, nil)

	bundle, err := NewBundle(cert, key)
	if err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(cert, bundle.Cert) {
		t.Error("Got nonsense for the cert in the bundle")
		return
	}
	if !bytes.Equal(key, bundle.PrivateKey) {
		t.Error("Got nonsense for the key in the bundle")
		return
	}

	if bundle.DomainName != "epcot.org" {
		t.Errorf("Did not get right DomainName: %s", bundle.DomainName)
	}

	if bundle.StartDate.Sub(time.Now()).Seconds() > 30 {
		t.Errorf("Did not get a resonable start date for the cert: %s", bundle.StartDate)
	}

	if bundle.ExpiresDate.Sub(time.Now().Add(time.Hour*24*15)).Seconds() > 30 {
		t.Errorf("Did not get a resonable end date for the cert: %s", bundle.ExpiresDate)
	}

	if len(bundle.AltNames) > 0 {
		t.Errorf("Bundle has alt names: %+v", bundle.AltNames)
	}
}

func TestNewBundleFromSecret(t *testing.T) {
	cert, key := getSelfSignedCert("epcot.org", 15, nil)

	s := &v1.Secret{
		Data: map[string][]byte{
			"tls.crt": cert,
			"tls.key": key,
		},
	}

	bundle, err := NewBundleFromSecret(s)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(cert, bundle.Cert) {
		t.Error("Got nonsense for the cert in the bundle")
	}
	if !bytes.Equal(key, bundle.PrivateKey) {
		t.Error("Got nonsense for the key in the bundle")
	}

	s = &v1.Secret{
		Data: map[string][]byte{},
	}

	bundle, err = NewBundleFromSecret(s)
	if err == nil {
		t.Error("Didn't get an error with an empty secret")
	}

	s = &v1.Secret{
		Data: map[string][]byte{
			"tls.crt": cert,
		},
	}

	bundle, err = NewBundleFromSecret(s)
	if err == nil {
		t.Error("Didn't get an error with an empty secret")
	}
}

func TestNewBundleSANInput(t *testing.T) {
	cert, key := getSelfSignedCert("epcot.org", 15, []string{"magic-kingdom.com"})

	bundle, err := NewBundle(cert, key)
	if err != nil {
		t.Error(err)
		return
	}

	if len(bundle.AltNames) == 0 {
		t.Error("Bundle has no alt names.")
	}

	if bundle.AltNames[0] != "magic-kingdom.com" {
		t.Errorf("Got strange altname: %+v", bundle.AltNames)
	}
}

func TestExpiringWithin(t *testing.T) {
	cert, key := getSelfSignedCert("epcot.org", 15, nil)

	bundle, err := NewBundle(cert, key)
	if err != nil {
		t.Error(err)
		return
	}

	if !bundle.ExpiringWithin(15) {
		t.Error("Bundle doesn't think it's expiring in 15 days")
	}
	if !bundle.ExpiringWithin(16) {
		t.Error("Bundle doesn't think it's expiring in 16 days")
	}
	if bundle.ExpiringWithin(14) {
		t.Error("Bundle thinks it's expiring in 14 days")
	}
	if bundle.ExpiringWithin(1) {
		t.Error("Bundle thinks it's expiring in 1 days")
	}
}

func TestToSecret(t *testing.T) {
	cert, key := getSelfSignedCert("epcot.org", 15, []string{"magic-kingdom.com"})

	bundle, err := NewBundle(cert, key)
	if err != nil {
		t.Error(err)
		return
	}

	labels := map[string]string{
		"foo": "bar",
	}
	s := bundle.ToSecret("test-secert", labels)

	if !bytes.Equal(s.Data["tls.crt"], cert) {
		t.Error("Cert did not get copied to the seceret correctly")
	}
	if !bytes.Equal(s.Data["tls.key"], key) {
		t.Error("Key did not get copied to the seceret correctly")
	}
	if s.ObjectMeta.Name != "test-secert" {
		t.Error("Name not set correctly")
	}
	if s.ObjectMeta.Labels["domain"] != "epcot.org" {
		t.Error("Domain label not set correctly")
	}
	if s.ObjectMeta.Labels["foo"] != "bar" {
		t.Error("argument labels not copied over")
	}
}

func TestCheckSum(t *testing.T) {
	type args struct {
		name string
		sans []string
	}

	tests := []struct {
		a     args
		b     args
		equal bool
		desc  string
	}{
		{
			a:     args{name: "epcot.org", sans: nil},
			b:     args{name: "epcot.org", sans: nil},
			equal: true,
			desc:  "same domain and no sans",
		},
		{
			a:     args{name: "epcot.org", sans: nil},
			b:     args{name: "Epcot.org", sans: nil},
			equal: true,
			desc:  "same domain (diff capitalization) and no sans",
		},
		{
			a:     args{name: "epcot.org", sans: nil},
			b:     args{name: "epcot.com", sans: nil},
			equal: false,
			desc:  "different domains and no sans",
		},
		{
			a:     args{name: "epcot.org", sans: []string{"www.epcot.org"}},
			b:     args{name: "epcot.org", sans: []string{"www.epcot.org"}},
			equal: true,
			desc:  "same domains and same basic sans",
		},
		{
			a:     args{name: "epcot.org", sans: []string{"www.epcot.org"}},
			b:     args{name: "epcot.org", sans: []string{"WWW.epcot.org"}},
			equal: true,
			desc:  "same domains and same basic sans",
		},
		{
			a:     args{name: "epcot.org", sans: []string{"WWW.epcot.org", "visit.epcot.org"}},
			b:     args{name: "epcot.org", sans: []string{"visit.epcot.org", "www.epcot.org"}},
			equal: true,
			desc:  "same domains and disordered sans",
		},
	}

	for _, test := range tests {
		bundleA := getTestBundle(test.a.name, 15, test.b.sans)
		bundleB := getTestBundle(test.b.name, 15, test.b.sans)

		if test.equal {
			if !bytes.Equal(bundleA.Checksum(), bundleB.Checksum()) {
				t.Errorf("Two bundles with the %s have a different checksum", test.desc)
			}
		} else {
			if bytes.Equal(bundleA.Checksum(), bundleB.Checksum()) {
				t.Errorf("Two bundles with the %s have the same checksum", test.desc)
			}
		}
	}
}

func TestSatisfiesCert(t *testing.T) {
	bundle := getTestBundle("epcot.org", 15, nil)
	cert := k8s.Certificate{
		Spec: k8s.CertificateSpec{
			Domain: "epcot.org",
		},
	}

	if !bundle.SatisfiesCert(cert) {
		t.Error("Bundle did no satisfy the cert when it should have")
	}

	bundle = getTestBundle("epcot.org", 15, []string{"www.epcot.org"})
	cert = k8s.Certificate{
		Spec: k8s.CertificateSpec{
			Domain:   "epcot.org",
			AltNames: []string{"WWW.epcot.org"},
		},
	}

	if !bundle.SatisfiesCert(cert) {
		t.Error("Bundle did no satisfy the cert when it should have")
	}
}

func getTestBundle(name string, days int, sans []string) *Bundle {
	cert, key := getSelfSignedCert(name, days, sans)
	bundle, err := NewBundle(cert, key)
	if err != nil {
		log.Fatal(err)
	}

	return bundle
}

func getSelfSignedCert(name string, days int, sans []string) ([]byte, []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"LW Test"},
			CommonName:   name,
		},
		NotBefore: time.Now().Add(time.Hour * -1),
		NotAfter:  time.Now().Add(time.Hour * 24 * time.Duration(days)),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if sans != nil {
		template.DNSNames = sans
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	cert := &bytes.Buffer{}
	pem.Encode(cert, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	key := &bytes.Buffer{}
	pem.Encode(key, &pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return cert.Bytes(), key.Bytes()

}
