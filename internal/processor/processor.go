// Copyright 2016 Google Inc. All Rights Reserved.
// Copyright 2016 Palm Stone Games, Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package processor

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/pkg/errors"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/rest"

	"liquidweb.com/kube-cert-manager/internal/ca/acme"
	"liquidweb.com/kube-cert-manager/internal/cert"
	"liquidweb.com/kube-cert-manager/internal/k8s"
)

type CertificateAuthority interface {
	ProvisionCert(*k8s.Certificate) (*cert.Bundle, error)
	RenewCert(*k8s.Certificate, *cert.Bundle) (*cert.Bundle, error)
}

// CertProcessor holds the shared configuration, state, and locks
type CertProcessor struct {
	acmeURL          string
	certNamespace    string
	tagPrefix        string
	namespaces       []string
	defaultCA        string
	defaultChallange string
	defaultEmail     string
	db               *bolt.DB
	Lock             sync.Mutex
	TLSLock          sync.Mutex
	kube             k8s.K8sClient
	renewBeforeDays  int
}

// NewCertProcessor creates and populates a CertProcessor
func NewCertProcessor(
	kubeclient *kubernetes.Clientset,
	certClient *rest.RESTClient,
	acmeURL string,
	certNamespace string,
	tagPrefix string,
	namespaces []string,
	defaultCA string,
	defaultChallange string,
	defaultEmail string,
	db *bolt.DB,
	renewBeforeDays int) *CertProcessor {
	return &CertProcessor{
		kube:             k8s.NewClient(kubeclient, certClient),
		acmeURL:          acmeURL,
		certNamespace:    certNamespace,
		tagPrefix:        tagPrefix,
		namespaces:       namespaces,
		defaultCA:        defaultCA,
		defaultChallange: defaultChallange,
		defaultEmail:     defaultEmail,
		db:               db,
		renewBeforeDays:  renewBeforeDays,
	}
}

func (p *CertProcessor) syncCertificates() error {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	certificates, err := p.GetCertificates()
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, cert := range certificates {
		wg.Add(1)
		go func(cert k8s.Certificate) {
			defer wg.Done()
			_, err := p.processCertificate(cert)
			if err != nil {
				log.Printf("Error while processing certificate during sync: %v", err)
			}
		}(cert)
	}
	wg.Wait()
	return nil
}

func (p *CertProcessor) getSecrets() ([]v1.Secret, error) {
	var secrets []v1.Secret
	if len(p.namespaces) == 0 {
		var err error
		secrets, err = p.kube.GetSecrets(v1.NamespaceAll)
		if err != nil {
			return nil, errors.Wrap(err, "Error while fetching secret list")
		}
	} else {
		for _, namespace := range p.namespaces {
			s, err := p.kube.GetSecrets(namespace)
			if err != nil {
				return nil, errors.Wrap(err, "Error while fetching secret list")
			}
			secrets = append(secrets, s...)
		}
	}
	return secrets, nil
}

func (p *CertProcessor) GetCertificates() ([]k8s.Certificate, error) {
	var certificates []k8s.Certificate
	if len(p.namespaces) == 0 {
		var err error
		certificates, err = p.kube.GetCertificates(v1.NamespaceAll)
		if err != nil {
			return nil, errors.Wrap(err, "Error while fetching certificate list")
		}
	} else {
		for _, namespace := range p.namespaces {
			certs, err := p.kube.GetCertificates(namespace)
			if err != nil {
				return nil, errors.Wrap(err, "Error while fetching certificate list")
			}
			certificates = append(certificates, certs...)
		}
	}
	return certificates, nil
}

func (p *CertProcessor) WatchKubernetesEvents(namespace string, wg *sync.WaitGroup, doneChan <-chan struct{}) {
	if namespace == v1.NamespaceAll {
		log.Printf("Watching certificates in all namespaces")
	} else {
		log.Printf("Watching certificates in namespace %s", namespace)
	}
	certEvents := p.kube.MonitorCertificateEvents(namespace, doneChan)
	for {
		select {
		case event := <-certEvents:
			err := p.processCertificateEvent(event)
			if err != nil {
				log.Printf("Error while processing certificate event: %v", err)
			}
		case <-doneChan:
			wg.Done()
			log.Println("Stopped certificate event watcher.")
			return
		}
	}
}

func (p *CertProcessor) Maintenance(syncInterval time.Duration, wg *sync.WaitGroup, doneChan <-chan struct{}) {
	for {
		select {
		case <-time.After(syncInterval):
			if err := p.syncCertificates(); err != nil {
				log.Printf("Error while synchronizing certificates during refresh: %s", err)
			}
			if err := p.gcSecrets(); err != nil {
				log.Printf("Error cleaning up secrets: %s", err)
			}
		case <-doneChan:
			wg.Done()
			log.Println("Stopped refresh loop.")
			return
		}
	}
}

func (p *CertProcessor) processCertificateEvent(c k8s.CertificateEvent) error {
	p.Lock.Lock()
	defer p.Lock.Unlock()
	switch c.Type {
	case "ADDED", "MODIFIED":
		_, err := p.processCertificate(c.Object)
		return err
	}
	return nil
}

// processCertificate creates or renews the corresponding secret
func (p *CertProcessor) processCertificate(certreq k8s.Certificate) (bool, error) {
	var certDetails *cert.Bundle

	if certreq.Status.Provisioned == "false" {
		//log.Printf("Cert %s/%s has already failed to provision.  Skipping.", cert.Metadata.Namespace, cert.Metadata.Name)
		return true, nil
	}

	if certreq.Spec.SecretName == "" {
		return p.noteCertError(certreq, nil, "Secret name not set")
	}

	err := p.fillInCertDefaults(certreq)

	if err != nil {
		return p.noteCertError(certreq, err, "Could not fill in defaults within the spec")
	}

	// Fetch current certificate data from k8s
	s, err := p.kube.GetSecret(certreq.Metadata.Namespace, certreq.Spec.SecretName)
	if err != nil {
		return p.noteCertError(certreq, err, "Error while fetching secret for domain %v", certreq.Spec.Domain)
	}

	certDetails, err = p.getCertFromSecret(s, certreq)

	if err != nil {
		return p.noteCertError(certreq, err, "Could not examine existing secret for correctness.")
	}

	if certDetails == nil {
		certDetails, err = p.getCachedCert(certreq)

		if err != nil {
			return p.noteCertError(certreq, err, "Couldn't lookup cached data for %v", certreq.Spec.Domain)
		}
	}

	// need to think about what happens when the ca for a cert changes...
	ca, err := p.caForCert(certreq)
	if err != nil {
		return p.noteCertError(certreq, err, "Could not get a CA for domain: %b", certreq.Spec.Domain)
	}

	// if we have a valid cert for the request, but it needs to be renewed... renew it.
	if certDetails.SatisfiesCert(certreq) && certDetails.ExpiringWithin(p.renewBeforeDays) {
		certDetails, err = ca.RenewCert(&certreq, certDetails)

		if err != nil {
			return p.noteCertError(certreq, err, "Error while renewing cert for new domain %v", certreq.Spec.Domain)
		}
		// if we don't have a cert, or the cert we have is no good, provision a cert
	} else if certDetails == nil || !certDetails.SatisfiesCert(certreq) {
		certDetails, err = ca.ProvisionCert(&certreq)

		if err != nil {
			return p.noteCertError(certreq, err, "Error while provisioning cert for new domain %v", certreq.Spec.Domain)
		}
	}

	err = p.saveCertToCache(certDetails)

	if err != nil {
		return p.noteCertError(certreq, err, "Error while syncing cert for %v to the backing cache", certreq.Spec.Domain)
	}

	// Convert cert data to k8s secret
	isUpdate := s != nil
	s = certDetails.ToSecret(certreq.Spec.SecretName, certreq.Metadata.Labels)

	if isUpdate {
		log.Printf("Updating secret %v in namespace %v for domain %v", s.Name, certreq.Metadata.Namespace, certreq.Spec.Domain)
	} else {
		log.Printf("Creating secret %v in namespace %v for domain %v", s.Name, certreq.Metadata.Namespace, certreq.Spec.Domain)
	}

	// Save the k8s secret
	if err := p.kube.SaveSecret(certreq.Metadata.Namespace, s, isUpdate); err != nil {
		return p.noteCertError(certreq, err, "Error while saving secret for domain %v", certreq.Spec.Domain)
	}

	msg := "Created certificate"
	if isUpdate {
		msg = "Updated certificate"
	}
	p.kube.CreateEvent(v1.Event{
		ObjectMeta: v1.ObjectMeta{
			Namespace: certreq.Metadata.Namespace,
		},
		InvolvedObject: v1.ObjectReference{
			Kind:      "Secret",
			Namespace: certreq.Metadata.Namespace,
			Name:      s.Name,
		},
		Reason:  "ACMEUpdated",
		Message: msg,
		Source: v1.EventSource{
			Component: "kube-cert-manager",
		},
		Type: "Normal",
	})

	now, _ := time.Now().UTC().MarshalText()
	exp, _ := certDetails.ExpiresDate().MarshalText()

	p.kube.UpdateCertStatus(certreq.Metadata.Namespace, certreq.Metadata.Name, k8s.CertificateStatus{
		Provisioned: "true",
		CreatedDate: string(now),
		ExpiresDate: string(exp),
	})

	return true, nil
}

func (p *CertProcessor) getCertFromSecret(s *v1.Secret, certreq k8s.Certificate) (*cert.Bundle, error) {
	// If a cert exists and altNames are correct, check its expiry and expected altNames
	// then if everything lines up, perform a renewal.
	if s != nil {
		certdata, err := cert.NewBundleFromSecret(s)

		if err != nil {
			return nil, errors.Wrapf(err, "Error while decoding certificate from secret for existing domain %v", certreq.Spec.Domain)
		}

		return certdata, nil
	}

	return nil, nil
}

func (p *CertProcessor) noteCertError(certreq k8s.Certificate, err error, format string, args ...interface{}) (bool, error) {
	namespace := certreq.Metadata.Namespace
	wrapped_err := errors.Wrapf(err, format, args)
	now, _ := time.Now().UTC().MarshalText()

	p.kube.UpdateCertStatus(namespace, certreq.Metadata.Name, k8s.CertificateStatus{
		Provisioned: "false",
		ErrorDate:   string(now),
		ErrorMsg:    wrapped_err.Error(),
	})

	return false, wrapped_err
}

func (p *CertProcessor) gcSecrets() error {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	// Fetch secrets before certificates. That way, if a race occurs,
	// we will only fail to delete a secret, not accidentally delete
	// one that's still referenced.
	secrets, err := p.getSecrets()
	if err != nil {
		return err
	}
	certs, err := p.GetCertificates()
	if err != nil {
		return err
	}
	usedSecrets := map[string]bool{}
	for _, cert := range certs {
		usedSecrets[cert.Metadata.Namespace+" "+cert.Spec.SecretName] = true
	}
	for _, secret := range secrets {
		if usedSecrets[secret.Namespace+" "+secret.Name] {
			continue
		}
		// need to replace to to use an annotation to mark the secret as from us
		log.Printf("Deleting unused secret %s in namespace %s", secret.Name, secret.Namespace)
		if err := p.kube.DeleteSecret(secret.Namespace, secret.Name); err != nil {
			return err
		}
	}
	return nil
}

func (p *CertProcessor) caForCert(certreq k8s.Certificate) (CertificateAuthority, error) {
	switch certreq.Spec.CA {
	case "letsencrypt":
		// TOMORROW - Get the http lock stuff figured out.  Create a new function for acme.
		return acme.NewAcmeCertAuthority(p.db, p.acmeURL), nil
	// case "globalsign":
	// 	return GlobalSignCertAuthority{"db": p.db}, nil
	default:
		return nil, fmt.Errorf("Unknown cert authority: %s", certreq.Spec.CA)
	}
}

func (p *CertProcessor) fillInCertDefaults(certreq k8s.Certificate) error {
	needUpdate := false

	if certreq.Spec.CA == "" {
		certreq.Spec.CA = p.defaultCA
		needUpdate = true
	}

	if certreq.Spec.Challange == "" {
		certreq.Spec.Challange = p.defaultChallange
		needUpdate = true
	}

	if certreq.Spec.Email == "" {
		certreq.Spec.Email = p.defaultEmail
		needUpdate = true
	}

	if needUpdate {
		return p.kube.UpdateCertSpec(certreq.Metadata.Namespace, certreq.Metadata.Name, certreq.Spec)
	}

	return nil
}
