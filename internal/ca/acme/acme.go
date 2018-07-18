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
	"liquidweb.com/kube-cert-manager/internal/cert"
	"liquidweb.com/kube-cert-manager/internal/k8s"
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

func NewAcmeCertAuthority(db *bolt.DB, acmeURL string) *certAuthority {
	return &certAuthority{
		db:           db,
		acmeURL:      acmeURL,
		httpProvider: newHttpRouteProvider(),
	}
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

func (ca *certAuthority) ProvisionCert(certreq *k8s.Certificate) (*cert.Bundle, error) {
	acmeClient, err := ca.init(certreq)

	if err == nil {
		return nil, err
	}

	domains := append([]string{certreq.Spec.Domain}, certreq.Spec.AltNames...)

	certRes, errs := acmeClient.ObtainCertificate(domains, true, nil, false)

	for _, domain := range domains {
		if errs[domain] != nil {
			return nil, errors.Wrapf(errs[domain], "Error while obtaining certificate for new domain %v", domain)
		}
	}

	ret := cert.Bundle{
		DomainName: certreq.Spec.Domain,
		AltNames:   certreq.Spec.AltNames,
		Cert:       certRes.Certificate,
		PrivateKey: certRes.PrivateKey,
		CAExtras: map[string]string{
			"CertStableURL": certRes.CertStableURL,
			"AccountRef":    certRes.AccountRef,
			"CertURL":       certRes.CertURL,
		},
	}

	return &ret, nil
}

func (ca *certAuthority) RenewCert(certreq *k8s.Certificate, certDetails *cert.Bundle) (*cert.Bundle, error) {
	acmeClient, err := ca.init(certreq)

	if err != nil {
		return nil, err
	}

	certReq := lego.CertificateResource{
		Domain:        certDetails.DomainName,
		Certificate:   certDetails.Cert,
		PrivateKey:    certDetails.PrivateKey,
		CertURL:       certDetails.CAExtras["CertURL"],
		CertStableURL: certDetails.CAExtras["CertStableURL"],
		AccountRef:    certDetails.CAExtras["AccountRef"],
	}

	certRes, err := acmeClient.RenewCertificate(certReq, true, false)

	if err != nil {
		return nil, errors.Wrapf(err, "Error while renewing certificate for domain %v", certreq.Spec.Domain)
	}

	ret := cert.Bundle{
		DomainName: certreq.Spec.Domain,
		AltNames:   certreq.Spec.AltNames,
		Cert:       certRes.Certificate,
		PrivateKey: certRes.PrivateKey,
		CAExtras: map[string]string{
			"CertStableURL": certRes.CertStableURL,
			"AccountRef":    certRes.AccountRef,
			"CertURL":       certRes.CertURL,
		},
	}

	return &ret, nil
}

func (ca *certAuthority) init(certreq *k8s.Certificate) (*lego.Client, error) {
	email := certreq.Spec.Email
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
		return ca.CreateNewUser(certreq, email)
	}

	if err := json.Unmarshal(userInfoRaw, &acmeUserInfo); err != nil {
		return nil, errors.Wrapf(err, "Error while unmarshalling user info for %v", certreq.Spec.Domain)
	}

	log.Printf("Creating ACME client for existing account %v, domain %v, and challange %v", email, certreq.Spec.Domain, certreq.Spec.Challange)
	return ca.newACMEClient(acmeUserInfo, certreq.Spec.Challange)
}

func (ca *certAuthority) CreateNewUser(certreq *k8s.Certificate, email string) (*lego.Client, error) {
	userKey, err := rsa.GenerateKey(rand.Reader, 2048)
	var acmeUserInfo ACMEUserData

	if err != nil {
		return nil, errors.Wrapf(err, "Error while generating rsa key for new user for domain %v", certreq.Spec.Domain)
	}

	acmeUserInfo.Email = email
	acmeUserInfo.Key = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(userKey),
	})

	log.Printf("Creating new ACME client for new account %v, domain %v, and challange type %v", email, certreq.Spec.Domain, certreq.Spec.Challange)
	acmeClient, err := ca.newACMEClient(acmeUserInfo, certreq.Spec.Challange)

	if err != nil {
		return nil, errors.Wrapf(err, "Error while creating ACME client for %v", certreq.Spec.Domain)
	}

	// Register
	acmeUserInfo.Registration, err = acmeClient.Register()
	if err != nil {
		return nil, errors.Wrapf(err, "Error while registering user for new domain %v", certreq.Spec.Domain)
	}

	// Agree to TOS
	if err = acmeClient.AgreeToTOS(); err != nil {
		return nil, errors.Wrapf(err, "Error while agreeing to acme TOS for new domain %v", certreq.Spec.Domain)
	}

	userInfoRaw, err := json.Marshal(&acmeUserInfo)
	if err != nil {
		return nil, errors.Wrapf(err, "Error while marshalling user info for domain %v", certreq.Spec.Domain)
	}

	// Save user info to bolt
	err = ca.db.Update(func(tx *bolt.Tx) error {
		key := []byte(email)
		tx.Bucket([]byte("acme-user-info")).Put(key, userInfoRaw)
		return nil
	})

	if err != nil {
		return nil, errors.Wrapf(err, "Error while saving user data to bolt for domain %v", certreq.Spec.Domain)
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
