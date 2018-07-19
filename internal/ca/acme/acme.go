package acme

import (
	"crypto"
	"encoding/json"
	"encoding/pem"
	"log"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	lego "github.com/xenolf/lego/acme"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/boltdb/bolt"
	"github.com/liquidweb/kube-cert-manager/internal/k8s"
	"github.com/liquidweb/kube-cert-manager/internal/tls"
)

type certAuthority struct {
	db           *bolt.DB
	acmeURL      string
	httpProvider *httpRouterProvider
}

type ACMEUserData struct {
	Email        string                     `json:"email"`
	Registration *lego.RegistrationResource `json:"registration"`
	Key          []byte                     `json:"key"`
}

type certDetails struct {
	Domain        string `json:"domain"`
	CertURL       string `json:"certUrl"`
	CertStableURL string `json:"certStableUrl"`
	AccountRef    string `json:"accountRef,omitempty"`
}

func NewAcmeCertAuthority(db *bolt.DB, acmeURL string) *certAuthority {
	return &certAuthority{
		db:           db,
		acmeURL:      acmeURL,
		httpProvider: newHttpRouteProvider(),
	}
}

func (ca *certAuthority) ProvisionCert(cert *k8s.Certificate) (*tls.Bundle, error) {
	acmeClient, err := ca.init(cert)

	if err == nil {
		return nil, err
	}

	domains := append([]string{cert.Spec.Domain}, cert.Spec.AltNames...)

	certRes, errs := acmeClient.ObtainCertificate(domains, true, nil, false)

	for _, domain := range domains {
		if errs[domain] != nil {
			return nil, errors.Wrapf(errs[domain], "Error while obtaining certificate for new domain %v", domain)
		}
	}
	ret, err := tls.NewBundle(certRes.Certificate, certRes.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse new cert from letsencrypt")
	}

	err = ca.saveCertDetails(certRes, ret)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to save cert details to the db for %s", cert.FQName())
	}

	return ret, nil
}

func (ca *certAuthority) RenewCert(cert *k8s.Certificate, bundle *tls.Bundle) (*tls.Bundle, error) {
	acmeClient, err := ca.init(cert)

	if err != nil {
		return nil, err
	}

	acmeDetails, err := ca.getCertDetails(bundle)
	if err != nil {
		return nil, err
	}

	acmereq := lego.CertificateResource{
		Domain:        bundle.DomainName,
		Certificate:   bundle.Cert,
		PrivateKey:    bundle.PrivateKey,
		CertURL:       acmeDetails.CertURL,
		CertStableURL: acmeDetails.CertStableURL,
		AccountRef:    acmeDetails.AccountRef,
	}

	certRes, err := acmeClient.RenewCertificate(acmereq, true, false)

	if err != nil {
		return nil, errors.Wrapf(err, "Error while renewing certificate for domain %v", cert.Spec.Domain)
	}

	err = ca.saveCertDetails(certRes, bundle)
	if err != nil {
		return nil, errors.Wrap(err, "could not save acme details to the db")
	}

	ret, err := tls.NewBundle(certRes.Certificate, certRes.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse new cert from letsencrypt")
	}

	return ret, nil
}

func (ca *certAuthority) init(cert *k8s.Certificate) (*lego.Client, error) {
	email := cert.Spec.Email
	var (
		userInfoRaw  []byte
		acmeUserInfo lego.User
	)

	err := ca.db.View(func(tx *bolt.Tx) error {
		userInfoRaw = tx.Bucket([]byte("acme-user-info")).Get([]byte(email))
		return nil
	})

	if err != nil {
		return nil, errors.Wrapf(err, "Error pulling cached user info for %s", email)
	}

	if userInfoRaw == nil {
		return ca.CreateNewUser(cert, email)
	}

	if err := json.Unmarshal(userInfoRaw, &acmeUserInfo); err != nil {
		return nil, errors.Wrapf(err, "Error while unmarshalling user info for %v", cert.Spec.Domain)
	}

	log.Printf("Creating ACME client for existing account %v, domain %v, and challange %v", email, cert.Spec.Domain, cert.Spec.Challange)
	return ca.newACMEClient(acmeUserInfo, cert.Spec.Challange)
}

func (ca *certAuthority) CreateNewUser(cert *k8s.Certificate, email string) (*lego.Client, error) {
	userKey, err := rsa.GenerateKey(rand.Reader, 2048)
	var acmeUserInfo ACMEUserData

	if err != nil {
		return nil, errors.Wrapf(err, "Error while generating rsa key for new user for domain %v", cert.Spec.Domain)
	}

	acmeUserInfo.Email = email
	acmeUserInfo.Key = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(userKey),
	})

	log.Printf("Creating new ACME client for new account %v, domain %v, and challange type %v", email, cert.Spec.Domain, cert.Spec.Challange)
	acmeClient, err := ca.newACMEClient(acmeUserInfo, cert.Spec.Challange)

	if err != nil {
		return nil, errors.Wrapf(err, "Error while creating ACME client for %v", cert.Spec.Domain)
	}

	// Register
	acmeUserInfo.Registration, err = acmeClient.Register()
	if err != nil {
		return nil, errors.Wrapf(err, "Error while registering user for new domain %v", cert.Spec.Domain)
	}

	// Agree to TOS
	if err = acmeClient.AgreeToTOS(); err != nil {
		return nil, errors.Wrapf(err, "Error while agreeing to acme TOS for new domain %v", cert.Spec.Domain)
	}

	userInfoRaw, err := json.Marshal(&acmeUserInfo)
	if err != nil {
		return nil, errors.Wrapf(err, "Error while marshalling user info for domain %v", cert.Spec.Domain)
	}

	// Save user info to bolt
	err = ca.db.Update(func(tx *bolt.Tx) error {
		key := []byte(email)
		tx.Bucket([]byte("acme-user-info")).Put(key, userInfoRaw)
		return nil
	})

	if err != nil {
		return nil, errors.Wrapf(err, "Error while saving user data to bolt for domain %v", cert.Spec.Domain)
	}

	return acmeClient, nil
}

func (ca *certAuthority) newACMEClient(acmeUser lego.User, challenge string) (*lego.Client, error) {
	acmeClient, err := lego.NewClient(ca.acmeURL, acmeUser, lego.RSA4096)
	if err != nil {
		return nil, errors.Wrap(err, "Error while generating acme client")
	}

	switch challenge {
	case "http":
		acmeClient.SetHTTPAddress(":5002")
		acmeClient.ExcludeChallenges([]lego.Challenge{lego.DNS01, lego.TLSSNI01})
		acmeClient.SetChallengeProvider(lego.HTTP01, ca.httpProvider)
		return acmeClient, nil
	default:
		return nil, errors.Errorf("Unknown challenge type: %v", challenge)
	}
}

func (ca *certAuthority) SetupRoute(router *mux.Router) {
	ca.httpProvider.SetupRoute(router)
}

func (ca *certAuthority) saveCertDetails(certres lego.CertificateResource, bundle *tls.Bundle) error {
	details := certDetails{
		Domain:        bundle.DomainName,
		CertURL:       certres.CertURL,
		CertStableURL: certres.CertStableURL,
		AccountRef:    certres.AccountRef,
	}

	asjson, err := json.Marshal(&details)
	if err != nil {
		return errors.Wrap(err, "could not marshall cert details into json")
	}
	// Save cert details to bolt
	err = ca.db.Update(func(tx *bolt.Tx) error {
		key := []byte(details.Domain)
		tx.Bucket([]byte("cert-details")).Put(key, asjson)
		return nil
	})
	if err != nil {
		return errors.Wrap(err, "could not save cert details to the db")
	}

	return nil
}

func (ca *certAuthority) getCertDetails(bundle *tls.Bundle) (*certDetails, error) {
	var asjson []byte
	err := ca.db.View(func(tx *bolt.Tx) error {
		asjson = tx.Bucket([]byte("cert-details")).Get([]byte(bundle.DomainName))
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not retrieve cert details from the db")
	}
	if asjson == nil {
		return nil, nil
	}

	var details certDetails
	err = json.Unmarshal(asjson, &details)
	if err != nil {
		return nil, errors.Wrap(err, "could not unmarshall details")
	}

	return &details, nil
}

func (u ACMEUserData) GetEmail() string {
	return u.Email
}

func (u ACMEUserData) GetRegistration() *lego.RegistrationResource {
	return u.Registration
}

func (u ACMEUserData) GetPrivateKey() crypto.PrivateKey {
	pemBlock, _ := pem.Decode(u.Key)
	if pemBlock.Type != "RSA PRIVATE KEY" {
		log.Printf("Invalid PEM user key: Expected RSA PRIVATE KEY, got %v", pemBlock.Type)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		log.Printf("Error while parsing private key: %v", err)
	}

	return privateKey
}
