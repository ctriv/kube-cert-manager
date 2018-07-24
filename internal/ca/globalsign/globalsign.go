package globalsign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
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
		return ca.handleHTTPProvisioning(cert)
	case "dns":
		return ca.handleDNSProvisioning(cert)
	default:
		return nil, errors.Errorf("Unsupported challange type: %s", cert.Spec.Challange)
	}
}

func (ca *certAuthority) RenewCert(cert *k8s.Certificate, certDetails *tls.Bundle) (*tls.Bundle, error) {
	return nil, nil
}

func (ca *certAuthority) handleHTTPProvisioning(cert *k8s.Certificate) (*tls.Bundle, error) {
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

	rawcert, err := ca.handleHTTPChallange(cert, orderRes)

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

func (ca *certAuthority) handleHTTPChallange(cert *k8s.Certificate, orderRes *URLVerificationResponse) ([]byte, error) {
	domain := strings.TrimPrefix(cert.Spec.Domain, "*.")
	var chalDomain string
	for _, possible := range orderRes.Response.VerificationURLList.VerificationURL {
		if possible == domain {
			chalDomain = domain
		}
	}

	if chalDomain == "" {
		return []byte{}, fmt.Errorf("Unable to find matching challange domain in list returned from globalsign: %s",
			strings.Join(orderRes.Response.VerificationURLList.VerificationURL, ", "),
		)
	}

	ca.addHTTPChallange(chalDomain, orderRes.Response.MetaTag)
	defer ca.removeHTTPChallange(chalDomain)

	request := &URLVerificationForIssue{
		Request: &QbV1UrlVerificationForIssueRequest{
			ApproverURL: chalDomain,
			OrderID:     orderRes.Response.OrderID,
		},
	}
	issueRes, err := ca.client.URLVerificationForIssue(request)

	if err != nil {
		return nil, errors.Wrapf(err, "could not complete cert order with the CA for the domain %v", cert.Spec.Domain)
	}

	if issueRes.Response.OrderResponseHeader.SuccessCode == -1 {
		return nil, ca.errFromOrderResponse(issueRes.Response.OrderResponseHeader)
	}

	issuedCert, err := ca.buildCertFromFulfillment(issueRes.Response.URLVerificationForIssue.Fulfillment)
	if err != nil {
		return nil, errors.Wrap(err, "globalsign returned a non-sensical cert chain")
	}

	return issuedCert, nil

}

func (ca *certAuthority) buildCertFromFulfillment(f *Fulfillment) ([]byte, error) {
	// the goal of this method is to contact the intermediate and server certs
	// together.
	// basically: $ cat www.example.com.crt bundle.crt > www.example.com.chained.crt
	server := f.ServerCertificate.X509Cert
	if server == "" {
		return []byte{}, errors.New("no x509 server cert returned")
	}

	var inter string

	for _, caCert := range f.CACertificates.CACertificate {
		if caCert.CACertType == "Inter" {
			inter = caCert.CACert
		}
	}

	if inter == "" {
		return []byte(server), nil
	}

	return []byte(server + inter), nil
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

func (ca *certAuthority) handleDNSProvisioning(cert *k8s.Certificate) (*tls.Bundle, error) {
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
