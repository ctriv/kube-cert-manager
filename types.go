package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"time"

	"github.com/pkg/errors"
	"github.com/xenolf/lego/acme"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/api/meta"
	"k8s.io/client-go/pkg/api/unversioned"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/rest"
)

// K8sClient provides convenience functions for handling resources this project
// cares about
// TODO: merge the two clients
type K8sClient struct {
	c          *kubernetes.Clientset
	certClient *rest.RESTClient
}

type WatchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

type CertificateEvent struct {
	Type   string      `json:"type"`
	Object Certificate `json:"object"`
}

type Certificate struct {
	unversioned.TypeMeta `json:",inline"`
	Metadata             api.ObjectMeta  `json:"metadata"`
	Spec                 CertificateSpec `json:"spec"`
	Status               CertificateStatus `json:"status,omitempty"`
}

type CertificateStatus struct {
	Provisioned string `json:"provisioned,omitempty"`
	CreatedDate string `json:"created,omitempty"`
	ExpiresDate string `json:"expires,omitempty"`
}

func (c *Certificate) GetObjectKind() unversioned.ObjectKind {
	return &c.TypeMeta
}

func (c *Certificate) GetObjectMeta() meta.Object {
	return &c.Metadata
}

type CertificateCopy Certificate

// Temporary workaround for https://github.com/kubernetes/client-go/issues/8
func (c *Certificate) UnmarshalJSON(data []byte) error {
	tmp := CertificateCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := Certificate(tmp)
	*c = tmp2
	return nil
}

type CertificateList struct {
	unversioned.TypeMeta `json:",inline"`
	Metadata             unversioned.ListMeta `json:"metadata"`
	Items                []Certificate        `json:"items"`
}

func (c *CertificateList) GetObjectKind() unversioned.ObjectKind {
	return &c.TypeMeta
}

func (c *CertificateList) GetListMeta() unversioned.List {
	return &c.Metadata
}

type CertificateListCopy CertificateList

// Temporary workaround for https://github.com/kubernetes/client-go/issues/8
func (cl *CertificateList) UnmarshalJSON(data []byte) error {
	tmp := CertificateListCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := CertificateList(tmp)
	*cl = tmp2
	return nil
}

type CertificateSpec struct {
	Domain     string   `json:"domain"`
	Provider   string   `json:"provider"`
	Email      string   `json:"email"`
	SecretName string   `json:"secretName"`
	AltNames   []string `json:"altNames"`
}

type ACMECertData struct {
	DomainName string
	Cert       []byte
	PrivateKey []byte
}



type ACMEUserData struct {
	Email        string                     `json:"email"`
	Registration *acme.RegistrationResource `json:"registration"`
	Key          []byte                     `json:"key"`
}

type ACMECertDetails struct {
	Domain        string `json:"domain"`
	CertURL       string `json:"certUrl"`
	CertStableURL string `json:"certStableUrl"`
	AccountRef    string `json:"accountRef,omitempty"`
}

func (u *ACMEUserData) GetEmail() string {
	return u.Email
}

func (u *ACMEUserData) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}

func (u *ACMEUserData) GetPrivateKey() crypto.PrivateKey {
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

// ToSecret creates a Kubernetes Secret from an ACME Certificate
func (c *ACMECertData) ToSecret(name string, labels map[string]string) *v1.Secret {
	var metadata v1.ObjectMeta
	metadata.Name = name

	metadata.Labels = map[string]string{
		"domain": c.DomainName,
		"creator": "kube-cert-manager",
	}

	for key, value := range labels {
	    metadata.Labels[key] = value
	}

	data := make(map[string][]byte)
	data["tls.crt"] = c.Cert
	data["tls.key"] = c.PrivateKey

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

func (c *ACMECertData) ExpiresDate() time.Time {
	block, _ := pem.Decode(c.Cert)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("Error while parsing cert expiration date: %s", err)
	}


	return cert.NotAfter
}

func NewACMECertDataFromSecret(s *v1.Secret, tagPrefix string) (ACMECertData, error) {
	var acmeCertData ACMECertData
	var ok bool

	acmeCertData.DomainName = getDomainFromLabel(s, tagPrefix)
	acmeCertData.Cert, ok = s.Data["tls.crt"]
	if !ok {
		return acmeCertData, errors.Errorf("Could not find key tls.crt in secret %v", s.Name)
	}
	acmeCertData.PrivateKey, ok = s.Data["tls.key"]
	if !ok {
		return acmeCertData, errors.Errorf("Could not find key tls.key in secret %v", s.Name)
	}
	return acmeCertData, nil
}

func NewACMECertDetailsFromResource(certRes acme.CertificateResource) ACMECertDetails {
	return ACMECertDetails{
		Domain:        certRes.Domain,
		CertURL:       certRes.CertURL,
		CertStableURL: certRes.CertStableURL,
		AccountRef:    certRes.AccountRef,
	}
}

func (certDetails *ACMECertDetails) ToCertResource() acme.CertificateResource {
	return acme.CertificateResource{
		Domain:        certDetails.Domain,
		CertURL:       certDetails.CertURL,
		CertStableURL: certDetails.CertStableURL,
		AccountRef:    certDetails.AccountRef,
	}
}
