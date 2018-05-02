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

	"liquidweb.com/kube-cert-manager/internal/cert"
	"liquidweb.com/kube-cert-manager/internal/k8s"
	"liquidweb.com/kube-cert-manager/internal/util"
)

type certAuthority struct {
	db     *bolt.DB
	lock   *sync.Mutex
	url    string
	client *ServerSSLV1
}

func NewGlobalsignCertAuthority(db *bolt.DB, url string) *certAuthority {
	return &certAuthority{
		db:     db,
		url:    url,
		lock:   &sync.Mutex{},
		client: NewServerSSLV1(url, true, &BasicAuth{}), // TODO get auth figured out
	}
}

func (ca *certAuthority) ProvisionCert(certreq *k8s.Certificate) (*cert.Bundle, error) {

	// need to figure out how to fire up the goroutine stuff to make this async
	switch certreq.Spec.Challange {
	case "http":
		return ca.handleHttpProvisioning(certreq)
	case "dns":
		return ca.handleDnsProvisioning(certreq)
	default:
		return nil, errors.Errorf("Unsupported challange type: %s", certreq.Spec.Challange)
	}
}

func (ca *certAuthority) RenewCert(certreq *k8s.Certificate, certDetails *cert.Bundle) (*cert.Bundle, error) {
	return nil, nil
}

func (ca *certAuthority) handleHttpProvisioning(certreq *k8s.Certificate) (*cert.Bundle, error) {
	// basic flow here is
	// 1. Create a CSR
	// 2. Create the request body to send to GS
	// 3. Fire off a URLVerification request
	// 4. Use the info from that request to prepare to the http challange.
	// 5. Once the challange is ready, send a URLVerificationForIssue request
	// 6. build a bundle and return it.
	privateKey, csr, err := ca.generateCSR(certreq)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not build keypair for %v", certreq.Spec.Domain)
	}

	initReq := ca.buildUrlVerificationRequest(certreq, csr)
	orderRes, err := ca.client.URLVerification(initReq)

	if err != nil {
		return nil, errors.Wrapf(err, "Could not start cert order with the CA for the domain %v", certreq.Spec.Domain)
	}

	if orderRes.Response.OrderResponseHeader.SuccessCode == -1 {
		return nil, ca.errFromOrderResponse(orderRes.Response.OrderResponseHeader)
	}

	return nil, nil
}

func (ca *certAuthority) errFromOrderResponse(res *OrderResponseHeader) error {
	var errorList []string

	for _, errorObj := range res.Errors.Error {
		errorList = append(errorList, errorObj.ErrorField)
	}

	return errors.New(strings.Join(errorList, "\n"))
}

func (ca *certAuthority) buildUrlVerificationRequest(certreq *k8s.Certificate, csr []byte) *URLVerification {
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

	if strings.HasPrefix(certreq.Spec.Domain, "*.") {
		initReq.Request.OrderRequestParameter.BaseOption = "wildcard"
	}

	if certreq.HasSANs() {
		entries := []*SANEntry{}
		for _, domain := range util.NormalizedAltNames(certreq.Spec.AltNames) {
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

func (ca *certAuthority) handleDnsProvisioning(certreq *k8s.Certificate) (*cert.Bundle, error) {
	return nil, errors.New("DNS Challange is supported but not yet implemented")
}

func (ca *certAuthority) generateCSR(certreq *k8s.Certificate) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Could not generate private key.")
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: certreq.Spec.Domain,
		},
	}

	if certreq.HasSANs() {
		template.DNSNames = util.NormalizedAltNames(certreq.Spec.AltNames)
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
