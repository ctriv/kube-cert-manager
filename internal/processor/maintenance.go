package processor

import (
	"log"
	"sync"
	"time"

	"github.com/liquidweb/kube-cert-manager/internal/k8s"
	"github.com/pkg/errors"
	"k8s.io/client-go/pkg/api/v1"
)

func (p *CertProcessor) Maintenance(syncInterval time.Duration, wg *sync.WaitGroup, doneChan <-chan struct{}) {
	for {
		select {
		case <-time.After(syncInterval):
			if err := p.syncCertificates(doneChan); err != nil {
				log.Printf("Error while synchronizing certificates during refresh: %s", err)
			}
			if err := p.gcSecrets(doneChan); err != nil {
				log.Printf("Error cleaning up secrets: %s", err)
			}
		case <-doneChan:
			p.maintWp.Stop()
			wg.Done()
			log.Println("Stopped maintenance loop.")
			return
		}
	}
}

func (p *CertProcessor) syncCertificates(doneChan <-chan struct{}) error {
	log.Println("Starting certificate sync")
	certificates, err := p.getCertificates()
	if err != nil {
		return errors.Wrap(err, "couldn't fetch certificates for sync")
	}

	var wg sync.WaitGroup
	for _, cert := range certificates {
		copy := cert
		wg.Add(1)
		p.maintWp.Submit(func() {
			defer wg.Done()
			_, err := p.processCertificate(copy, true)
			if err != nil {
				log.Printf("Error while processing certificate during sync: %v", err)
			}
		})
	}

	runDone := make(chan struct{})
	go func() {
		wg.Wait()
		log.Println("Completed certificate sync")
		close(runDone)
	}()
	select {
	case <-doneChan:
		// the program is exiting,
	case <-runDone:
		// we've finished all the jobs for this run
	}

	return nil
}

func (p *CertProcessor) gcSecrets(doneChan <-chan struct{}) error {
	// Fetch secrets before certificates. That way, if a race occurs,
	// we will only fail to delete a secret, not accidentally delete
	// one that's still referenced.
	log.Println("Starting secret gc")
	secrets, err := p.getSecrets()
	if err != nil {
		return errors.Wrap(err, "couldn't get secrets for gc")
	}
	certs, err := p.getCertificates()
	if err != nil {
		return errors.Wrap(err, "couldn't get certs for gc")
	}
	usedSecrets := map[string]bool{}
	for _, cert := range certs {
		usedSecrets[cert.Metadata.Namespace+" "+cert.Spec.SecretName] = true
	}

	var wg sync.WaitGroup
	for _, secret := range secrets {
		if usedSecrets[secret.Namespace+" "+secret.Name] {
			continue
		}
		wg.Add(1)
		copy := secret
		p.maintWp.Submit(func() {
			defer wg.Done()
			// need to replace to to use an annotation to mark the secret as from us
			log.Printf("Deleting unused secret %s in namespace %s", copy.Name, copy.Namespace)
			if err := p.k8s.DeleteSecret(copy.Namespace, copy.Name); err != nil {
				log.Printf("Error deleting secret %s/%s: %v", copy.Namespace, copy.Name, err)
			}
		})
	}

	runDone := make(chan struct{})
	go func() {
		wg.Wait()
		log.Println("Completed secret gc")
		close(runDone)
	}()
	select {
	case <-doneChan:
		// the program is exiting,
	case <-runDone:
		// we've finished all the jobs for this run
	}

	return nil
}

func (p *CertProcessor) getSecrets() ([]v1.Secret, error) {
	var secrets []v1.Secret
	if len(p.Namespaces) == 0 {
		var err error
		secrets, err = p.k8s.GetSecrets(v1.NamespaceAll)
		if err != nil {
			return nil, errors.Wrap(err, "Error while fetching secret list")
		}
	} else {
		for _, namespace := range p.Namespaces {
			s, err := p.k8s.GetSecrets(namespace)
			if err != nil {
				return nil, errors.Wrap(err, "Error while fetching secret list")
			}
			secrets = append(secrets, s...)
		}
	}
	return secrets, nil
}

func (p *CertProcessor) getCertificates() ([]k8s.Certificate, error) {
	var certificates []k8s.Certificate
	if len(p.Namespaces) == 0 {
		var err error
		certificates, err = p.k8s.GetCertificates(v1.NamespaceAll)
		if err != nil {
			return nil, errors.Wrap(err, "Error while fetching certificate list")
		}
	} else {
		for _, namespace := range p.Namespaces {
			certs, err := p.k8s.GetCertificates(namespace)
			if err != nil {
				return nil, errors.Wrap(err, "Error while fetching certificate list")
			}
			certificates = append(certificates, certs...)
		}
	}
	return certificates, nil
}
