package processor

import (
	"encoding/json"

	"github.com/boltdb/bolt"
	"github.com/pkg/errors"

	"liquidweb.com/kube-cert-manager/internal/cert"
	"liquidweb.com/kube-cert-manager/internal/k8s"
)

func (p *CertProcessor) saveCertToCache(certDetails *cert.Bundle) error {
	// Serialize acmeCertDetails and acmeUserInfo
	certDetailsRaw, err := json.Marshal(&certDetails)
	if err != nil {
		return errors.Wrapf(err, "Error while marshalling cert details for domain %v", certDetails.DomainName)
	}

	// Save cert details to bolt
	err = p.db.Update(func(tx *bolt.Tx) error {
		key := certDetails.Checksum()
		tx.Bucket([]byte("cert-details")).Put(key, certDetailsRaw)
		return nil
	})

	if err != nil {
		return errors.Wrapf(err, "Error while saving data to bolt for domain %v", certDetails.DomainName)
	}

	return nil
}

func (p *CertProcessor) getCachedCert(certreq k8s.Certificate) (*cert.Bundle, error) {
	// cert details from bolt
	var jsonblob []byte
	var cachedCertDetails cert.Bundle
	err := p.db.View(func(tx *bolt.Tx) error {
		jsonblob = tx.Bucket([]byte("cert-details")).Get(certreq.Checksum())
		return nil
	})

	if err != nil {
		return nil, errors.Wrapf(err, "Error while running bolt view transaction for domain %v", certreq.Spec.Domain)
	}

	err = json.Unmarshal(jsonblob, &cachedCertDetails)

	if err != nil {
		return nil, errors.Wrapf(err, "Could not unmarshal json blob for domain %v", certreq.Spec.Domain)
	}

	return &cachedCertDetails, nil
}
