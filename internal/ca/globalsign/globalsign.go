package globalsign

import (
	"sync"

	"github.com/boltdb/bolt"

	"liquidweb.com/kube-cert-manager/internal/cert"
	"liquidweb.com/kube-cert-manager/internal/k8s"
)

type GlobalsignCertAuthority struct {
	db   *bolt.DB
	lock *sync.Mutex
	url  string
}

func NewGlobalsignCertAuthority(db *bolt.DB, url string) *GlobalsignCertAuthority {
	return &GlobalsignCertAuthority{
		db:   db,
		url:  url,
		lock: &sync.Mutex{},
	}
}

func (gs *GlobalsignCertAuthority) ProvisionCert(certreq *k8s.Certificate) (*cert.Bundle, error) {
	return nil, nil
}

func (gs *GlobalsignCertAuthority) RenewCert(certreq *k8s.Certificate, certDetails *cert.Bundle) (*cert.Bundle, error) {
	return nil, nil
}
