package globalsign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"sync"

	"github.com/boltdb/bolt"
	"github.com/pkg/errors"

	"github.com/liquidweb/kube-cert-manager/internal/k8s"
	"github.com/liquidweb/kube-cert-manager/internal/tls"
	"github.com/liquidweb/kube-cert-manager/internal/util"
)

type certAuthority struct {
	url        string
	client     *ServerSSLV1
	challanges *sync.Map
}

func NewGlobalsignCertAuthority(db *bolt.DB, url string) *certAuthority {
	return &certAuthority{
		url:        url,
		client:     NewServerSSLV1(url, true, &BasicAuth{}), // TODO get auth figured out
		challanges: new(sync.Map),
	}
}

func (ca *certAuthority) ProvisionCert(cert *k8s.Certificate) (*tls.Bundle, error) {
	switch cert.Spec.Challange {
	case "http":
		return ca.handleHttpProvisioning(cert)
	case "dns":
		return ca.handleDnsProvisioning(cert)
	default:
		return nil, errors.Errorf("Unsupported challange type: %s", cert.Spec.Challange)
	}
}

func (ca *certAuthority) RenewCert(cert *k8s.Certificate, certDetails *tls.Bundle) (*tls.Bundle, error) {
	return nil, nil
}

func (ca *certAuthority) handleHttpProvisioning(cert *k8s.Certificate) (*tls.Bundle, error) {
	// basic flow here is
	// 1. Create a CSR
	// 2. Create the request body to send to GS
	// 3. Fire off a URLVerification request
	// 4. Use the info from that request to prepare for the http challange.
	// 5. Once the challange is ready, send a URLVerificationForIssue request
	// 6. build a bundle and return it.
	privateKey, csr, err := ca.generateCSR(cert)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not build keypair for %v", cert.Spec.Domain)
	}

	initReq := ca.buildUrlVerificationRequest(cert, csr)
	orderRes, err := ca.client.URLVerification(initReq)

	if err != nil {
		return nil, errors.Wrapf(err, "Could not start cert order with the CA for the domain %v", cert.Spec.Domain)
	}

	if orderRes.Response.OrderResponseHeader.SuccessCode == -1 {
		return nil, ca.errFromOrderResponse(orderRes.Response.OrderResponseHeader)
	}

	rawcert, err := ca.handleHttpChallange(cert, orderRes)

	if err != nil {
		return nil, err
	}

	bundle, err := tls.NewBundle(rawcert, privateKey)

	if err != nil {
		return nil, errors.Wrap(err, "unable to parse newly provisioned cert from globalsign")
	}

	bundle.CADetails = map[string]string{
		"orderId": orderRes.Response.OrderID,
	}

	return bundle, nil
}

func (ca *certAuthority) handleHttpChallange(cert *k8s.Certificate, orderRes *URLVerificationResponse) ([]byte, error) {
	return []byte("write me"), nil
}

func (ca *certAuthority) errFromOrderResponse(res *OrderResponseHeader) error {
	var errorList []string

	for _, errorObj := range res.Errors.Error {
		errorList = append(errorList, errorObj.ErrorField)
	}

	return errors.New(strings.Join(errorList, "\n"))
}

func (ca *certAuthority) buildUrlVerificationRequest(cert *k8s.Certificate, csr []byte) *URLVerification {
	initReq := &URLVerification{
		Request: &QbV1UrlVerificationRequest{
			OrderRequestParameter: &OrderRequestParameter{
				ProductCode: "DV_HIGH_URL_SHA2",
				OrderKind:   "new",
				ValidityPeriod: &ValidityPeriod{
					Months: "12",
				},
				CSR: string(csr),
			},
			ContactInfo: ca.defaultContactInfo(),
		},
	}

	if strings.HasPrefix(cert.Spec.Domain, "*.") {
		initReq.Request.OrderRequestParameter.BaseOption = "wildcard"
	}

	if cert.HasSANs() {
		entries := []*SANEntry{}
		for _, domain := range util.NormalizedAltNames(cert.Spec.AltNames) {
			entries = append(entries, &SANEntry{
				SubjectAltName: domain,
				SANOptionType:  "2",
			})
		}

		initReq.Request.SANEntries = &SANEntries{
			SANEntry: entries,
		}

		initReq.Request.OrderRequestParameter.Options = &Options{
			Option: []*Option{&Option{
				OptionName:  "SAN",
				OptionValue: "True",
			}},
		}
	}

	return initReq
}

func (ca *certAuthority) defaultContactInfo() *ContactInfo {
	return &ContactInfo{
		FirstName: "Liquid",
		LastName:  "Web",
		Phone:     "800-580-4985",
		Email:     "ssl-services@liquidweb.com",
	}
}

func (ca *certAuthority) handleDnsProvisioning(cert *k8s.Certificate) (*tls.Bundle, error) {
	return nil, errors.New("DNS Challange is not implemented")
}

func (ca *certAuthority) generateCSR(cert *k8s.Certificate) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Could not generate private key.")
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cert.Spec.Domain,
		},
	}

	if cert.HasSANs() {
		template.DNSNames = util.NormalizedAltNames(cert.Spec.AltNames)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)

	if err != nil {
		errors.Wrap(err, "Could not generate csr key")
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemKey := pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	privateKeyBlock := pem.EncodeToMemory(&pemKey)

	pemCSR := pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}
	csrBlock := pem.EncodeToMemory(&pemCSR)

	return privateKeyBlock, csrBlock, nil
}
