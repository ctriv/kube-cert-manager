package globalsign

import (
	"sync"

	"github.com/boltdb/bolt"

	"liquidweb.com/kube-cert-manager/internal/cert"
	"liquidweb.com/kube-cert-manager/internal/k8s"
)

type certAuthority struct {
	db   *bolt.DB
	lock *sync.Mutex
	url  string
}

func NewGlobalsignCertAuthority(db *bolt.DB, url string) *certAuthority {
	return &certAuthority{
		db:   db,
		url:  url,
		lock: &sync.Mutex{},
	}
}

func (ca *certAuthority) ProvisionCert(certreq *k8s.Certificate) (*cert.Bundle, error) {
	return nil, nil
}

func (ca *certAuthority) RenewCert(certreq *k8s.Certificate, certDetails *cert.Bundle) (*cert.Bundle, error) {
	return nil, nil
}
