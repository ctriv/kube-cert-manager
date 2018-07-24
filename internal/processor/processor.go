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
	"time"

	"github.com/boltdb/bolt"
	"github.com/gammazero/workerpool"
	"github.com/gorilla/mux"
	"github.com/liquidweb/kube-cert-manager/internal/ca/acme"
	"github.com/liquidweb/kube-cert-manager/internal/ca/globalsign"
	"github.com/liquidweb/kube-cert-manager/internal/k8s"
	"github.com/liquidweb/kube-cert-manager/internal/tls"
	"github.com/pkg/errors"
	"github.com/vburenin/nsync"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/rest"
)

// CertProcessor holds the shared configuration, state, and locks
type CertProcessor struct {
	acmeURL          string
	certSecretPrefix string
	certNamespace    string
	tagPrefix        string
	Namespaces       []string
	defaultChallange string
	defaultCA        string
	defaultEmail     string
	db               *bolt.DB
	k8s              k8s.K8sClient
	renewBeforeDays  int
	wp               *workerpool.WorkerPool
	maintWp          *workerpool.WorkerPool
	locks            *nsync.NamedMutex
	CAs              map[string]certificateAuthority
}

type certificateAuthority interface {
	ProvisionCert(*k8s.Certificate) (*tls.Bundle, error)
	RenewCert(*k8s.Certificate, *tls.Bundle) (*tls.Bundle, error)
	SetupRoute(*mux.Router)
}

// NewCertProcessor creates and populates a CertProcessor
func NewCertProcessor(
	kubeclient *kubernetes.Clientset,
	certClient *rest.RESTClient,
	acmeURL string,
	globalSignURL string,
	namespaces []string,
	defaultCA string,
	defaultChallange string,
	defaultEmail string,
	db *bolt.DB,
	renewBeforeDays int,
	workers int) *CertProcessor {
	p := &CertProcessor{
		k8s:              k8s.NewK8sClient(kubeclient, certClient),
		acmeURL:          acmeURL,
		Namespaces:       namespaces,
		defaultChallange: defaultChallange,
		defaultCA:        defaultCA,
		defaultEmail:     defaultEmail,
		db:               db,
		renewBeforeDays:  renewBeforeDays,
		wp:               workerpool.New(workers),
		maintWp:          workerpool.New(workers),
		locks:            nsync.NewNamedMutex(),
		CAs: map[string]certificateAuthority{
			"letsencrypt": acme.NewAcmeCertAuthority(db, acmeURL),
		},
	}

	if globalSignURL != "" {
		p.CAs["globalsign"] = globalsign.NewGlobalsignCertAuthority(db, globalSignURL)
	}

	return p
}

// processCertificate creates or renews the corresponding secret
// processCertificate will create new ACME users if necessary, and complete ACME challenges
// processCertificate caches ACME user and certificate information in boltdb for reuse
func (p *CertProcessor) processCertificate(cert k8s.Certificate, forMaint bool) (bool, error) {
	var (
		bundle *tls.Bundle
	)

	gotlock := p.locks.TryLock(cert.FQName())
	if !gotlock {
		log.Printf("[%s] Cert is currently being worked on, skipping...", cert.FQName())
		return false, nil
	}
	defer p.locks.Unlock(cert.FQName())

	if !forMaint {
		log.Printf("[%s] Starting work", cert.FQName())
	}

	if cert.Status.Provisioned == "false" {
		// p.deleteFailedCertIfNeeded(cert, namespace)
		return true, nil
	}

	if cert.Status.Provisioned == "true" && !forMaint {
		// we don't currently support updates to the cert.  Once we're on a newer
		// kube api with support for generation updates, we can do updates.
		return false, nil
	}

	if cert.Spec.SecretName == "" {
		newerr := errors.New("Cannot process cert")
		return p.NoteCertError(cert, newerr, "spec.secretName is not set.")
	}

	err := p.fillInCertDefaults(cert)
	if err != nil {
		return p.NoteCertError(cert, err, "could not fill out defaults.")
	}

	// need to think about what happens when the ca for a cert changes...
	ca, err := p.caForCert(cert)
	if err != nil {
		return p.NoteCertError(cert, err, "Could not get a CA")
	}

	namespace := cert.Metadata.Namespace

	// Fetch current certificate data from k8s
	s, err := p.k8s.GetSecret(namespace, cert.Spec.SecretName)
	if err != nil {
		return p.NoteCertError(cert, err, "Error while fetching certificate secret data for domain %v", cert.Spec.Domain)
	}

	// Once MWX is updated this can be turned on.
	// if s != nil && !forMaint && cert.Status.Provisioned == "" {
	// 	return p.NoteCertError(cert, err, "Duplicate cert request for secret %s/%s", namespace, p.secretName(cert))
	// }

	if s != nil {
		bundle, err = tls.NewBundleFromSecret(s)
		if err != nil {
			return p.NoteCertError(cert, err, "Could not parse existing cert in secret %s", cert.Spec.SecretName)
		}

		// If certificate expires after now + p.renewBeforeDays, don't renew
		if bundle.SatisfiesCert(cert) && !bundle.ExpiringWithin(p.renewBeforeDays) {
			// if we've got dup request for already created secret, just return that we're done.
			// once MWX is updated, this can be replaced with the failure logic above.
			if cert.Status.Provisioned == "" {
				log.Printf("[%s] Setting status to reflect the existance of the secret", cert.FQName())
				created, _ := bundle.StartDate.MarshalText()
				expires, _ := bundle.ExpiresDate.MarshalText()

				p.k8s.UpdateCertStatus(namespace, cert.Metadata.Name, k8s.CertificateStatus{
					Provisioned: "true",
					CreatedDate: string(created),
					ExpiresDate: string(expires),
				})
			}
			return false, nil
		}

		log.Printf("[%v] Expiry for cert is in less than %v days (%v), attempting renewal", cert.Spec.Domain, p.renewBeforeDays, bundle.ExpiresDate.String())
		bundle, err = ca.RenewCert(&cert, bundle)
		if err != nil {
			return p.NoteCertError(cert, err, "Error while renewing certificate")
		}
	} else {
		bundle, err = ca.ProvisionCert(&cert)
		if err != nil {
			return p.NoteCertError(cert, err, "Error while provisioning new certificate")
		}
	}

	// Convert cert data to k8s secret
	isUpdate := s != nil
	s = bundle.ToSecret(cert.Spec.SecretName, cert.Metadata.Labels)

	if isUpdate {
		log.Printf("Updating secret %v in namespace %v for domain %v", s.Name, namespace, cert.Spec.Domain)
	} else {
		log.Printf("Creating secret %v in namespace %v for domain %v", s.Name, namespace, cert.Spec.Domain)
	}

	// Save the k8s secret
	if err := p.k8s.SaveSecret(namespace, s, isUpdate); err != nil {
		return p.NoteCertError(cert, err, "Error while saving secret for domain %v", cert.Spec.Domain)
	}

	msg := "Created certificate"
	if isUpdate {
		msg = "Updated certificate"
	}
	p.k8s.CreateEvent(v1.Event{
		ObjectMeta: v1.ObjectMeta{
			Namespace: namespace,
		},
		InvolvedObject: v1.ObjectReference{
			Kind:      "Secret",
			Namespace: namespace,
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
	exp, _ := bundle.ExpiresDate.MarshalText()

	p.k8s.UpdateCertStatus(namespace, cert.Metadata.Name, k8s.CertificateStatus{
		Provisioned: "true",
		CreatedDate: string(now),
		ExpiresDate: string(exp),
		CADetails:   bundle.CADetails,
	})

	return true, nil
}

func (p *CertProcessor) NoteCertError(cert k8s.Certificate, err error, format string, args ...interface{}) (bool, error) {
	wrappedErr := errors.Wrapf(err, format, args)
	now, _ := time.Now().UTC().MarshalText()

	p.k8s.UpdateCertStatus(cert.Metadata.Namespace, cert.Metadata.Name, k8s.CertificateStatus{
		Provisioned: "false",
		ErrorDate:   string(now),
		ErrorMsg:    wrappedErr.Error(),
	})

	return false, wrappedErr
}

func (p *CertProcessor) caForCert(certreq k8s.Certificate) (certificateAuthority, error) {
	ca, ok := p.CAs[certreq.Spec.CA]

	if !ok {
		return nil, fmt.Errorf("Unknown cert authority for %s: %s", certreq.FQName(), certreq.Spec.CA)
	}

	return ca, nil
}

func (p *CertProcessor) deleteFailedCertIfNeeded(c k8s.Certificate, namespace string) {
	cutoff := c.Metadata.CreationTimestamp.Time.UTC().AddDate(0, 0, 7)

	if cutoff.Before(time.Now().UTC()) {
		err := p.k8s.DeleteCertificate(c, namespace)
		if err != nil {
			log.Printf("Error deleting cert %s with error %s", c.Metadata.Name, err)
		}
	}
}

func (p *CertProcessor) fillInCertDefaults(cert k8s.Certificate) error {
	needUpdate := false

	if cert.Spec.CA == "" {
		cert.Spec.CA = p.defaultCA
		needUpdate = true
	}

	if cert.Spec.Challange == "" {
		cert.Spec.Challange = p.defaultChallange
		needUpdate = true
	}

	if cert.Spec.Email == "" {
		cert.Spec.Email = p.defaultEmail
		needUpdate = true
	}

	if needUpdate {
		return p.k8s.UpdateCertSpec(cert.Metadata.Namespace, cert.Metadata.Name, cert.Spec)
	}

	return nil
}
