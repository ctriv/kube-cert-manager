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

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gammazero/workerpool"
	"github.com/pkg/errors"
	"github.com/vburenin/nsync"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns/cloudflare"
	"github.com/xenolf/lego/providers/dns/digitalocean"
	"github.com/xenolf/lego/providers/dns/dnsimple"
	"github.com/xenolf/lego/providers/dns/dnsmadeeasy"
	"github.com/xenolf/lego/providers/dns/dnspod"
	"github.com/xenolf/lego/providers/dns/dyn"
	"github.com/xenolf/lego/providers/dns/gandi"
	"github.com/xenolf/lego/providers/dns/googlecloud"
	"github.com/xenolf/lego/providers/dns/linode"
	"github.com/xenolf/lego/providers/dns/namecheap"
	"github.com/xenolf/lego/providers/dns/ovh"
	"github.com/xenolf/lego/providers/dns/pdns"
	"github.com/xenolf/lego/providers/dns/rfc2136"
	"github.com/xenolf/lego/providers/dns/route53"
	"github.com/xenolf/lego/providers/dns/vultr"
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
	namespaces       []string
	defaultProvider  string
	defaultEmail     string
	db               *bolt.DB
	httpProvider     *httpRouterProvider
	k8s              K8sClient
	renewBeforeDays  int
	wp               *workerpool.WorkerPool
	maintWp          *workerpool.WorkerPool
	locks            *nsync.NamedMutex
}

// NewCertProcessor creates and populates a CertProcessor
func NewCertProcessor(
	k8s *kubernetes.Clientset,
	certClient *rest.RESTClient,
	acmeURL string,
	certSecretPrefix string,
	certNamespace string,
	tagPrefix string,
	namespaces []string,
	defaultProvider string,
	defaultEmail string,
	db *bolt.DB,
	renewBeforeDays int,
	workers int) *CertProcessor {
	return &CertProcessor{
		k8s:              K8sClient{c: k8s, certClient: certClient},
		acmeURL:          acmeURL,
		certSecretPrefix: certSecretPrefix,
		certNamespace:    certNamespace,
		tagPrefix:        tagPrefix,
		namespaces:       namespaces,
		defaultProvider:  defaultProvider,
		defaultEmail:     defaultEmail,
		db:               db,
		renewBeforeDays:  renewBeforeDays,
		httpProvider:     newHttpRouterProvider(),
		wp:               workerpool.New(workers),
		maintWp:          workerpool.New(workers),
		locks:            nsync.NewNamedMutex(),
	}
}

func (p *CertProcessor) newACMEClient(acmeUser acme.User, provider string) (*acme.Client, *sync.Mutex, error) {
	acmeClient, err := acme.NewClient(p.acmeURL, acmeUser, acme.RSA2048)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error while generating acme client")
	}

	initDNSProvider := func(p acme.ChallengeProvider, err error) (*acme.Client, *sync.Mutex, error) {
		if err != nil {
			return nil, nil, errors.Wrapf(err, "Error while initializing challenge provider %v", provider)
		}

		if err := acmeClient.SetChallengeProvider(acme.DNS01, p); err != nil {
			return nil, nil, errors.Wrapf(err, "Error while setting challenge provider %v for dns-01", provider)
		}

		acmeClient.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})
		return acmeClient, nil, nil
	}

	switch provider {
	case "http":
		acmeClient.SetHTTPAddress(":5002")
		acmeClient.SetChallengeProvider(acme.HTTP01, p.httpProvider)
		acmeClient.ExcludeChallenges([]acme.Challenge{acme.DNS01, acme.TLSSNI01})
		return acmeClient, nil, nil
	case "cloudflare":
		return initDNSProvider(cloudflare.NewDNSProvider())
	case "digitalocean":
		return initDNSProvider(digitalocean.NewDNSProvider())
	case "dnsimple":
		return initDNSProvider(dnsimple.NewDNSProvider())
	case "dnsmadeeasy":
		return initDNSProvider(dnsmadeeasy.NewDNSProvider())
	case "dnspod":
		return initDNSProvider(dnspod.NewDNSProvider())
	case "dyn":
		return initDNSProvider(dyn.NewDNSProvider())
	case "gandi":
		return initDNSProvider(gandi.NewDNSProvider())
	case "googlecloud":
		return initDNSProvider(googlecloud.NewDNSProvider())
	case "linode":
		return initDNSProvider(linode.NewDNSProvider())
	case "namecheap":
		return initDNSProvider(namecheap.NewDNSProvider())
	case "ovh":
		return initDNSProvider(ovh.NewDNSProvider())
	case "pdns":
		return initDNSProvider(pdns.NewDNSProvider())
	case "rfc2136":
		return initDNSProvider(rfc2136.NewDNSProvider())
	case "route53":
		return initDNSProvider(route53.NewDNSProvider())
	case "vultr":
		return initDNSProvider(vultr.NewDNSProvider())
	default:
		return nil, nil, errors.Errorf("Unknown provider %v", provider)
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
		usedSecrets[cert.Metadata.Namespace+" "+p.secretName(cert)] = true
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
			if err := p.k8s.deleteSecret(copy.Namespace, copy.Name); err != nil {
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
	if len(p.namespaces) == 0 {
		var err error
		secrets, err = p.k8s.getSecrets(v1.NamespaceAll)
		if err != nil {
			return nil, errors.Wrap(err, "Error while fetching secret list")
		}
	} else {
		for _, namespace := range p.namespaces {
			s, err := p.k8s.getSecrets(namespace)
			if err != nil {
				return nil, errors.Wrap(err, "Error while fetching secret list")
			}
			secrets = append(secrets, s...)
		}
	}
	return secrets, nil
}

func (p *CertProcessor) getCertificates() ([]Certificate, error) {
	var certificates []Certificate
	if len(p.namespaces) == 0 {
		var err error
		certificates, err = p.k8s.getCertificates(v1.NamespaceAll)
		if err != nil {
			return nil, errors.Wrap(err, "Error while fetching certificate list")
		}
	} else {
		for _, namespace := range p.namespaces {
			certs, err := p.k8s.getCertificates(namespace)
			if err != nil {
				return nil, errors.Wrap(err, "Error while fetching certificate list")
			}
			certificates = append(certificates, certs...)
		}
	}
	return certificates, nil
}

func (p *CertProcessor) watchKubernetesEvents(namespace string, wg *sync.WaitGroup, doneChan <-chan struct{}) {
	if namespace == v1.NamespaceAll {
		log.Printf("Watching certificates in all namespaces")
	} else {
		log.Printf("Watching certificates in namespace %s", namespace)
	}

	certEvents := p.k8s.monitorCertificateEvents(namespace, doneChan)
	for {
		select {
		case event := <-certEvents:
			p.wp.Submit(func() {
				err := p.processCertificateEvent(event)
				if err != nil {
					log.Printf("Error while processing certificate event: %v", err)
				}
			})
		case <-doneChan:
			p.wp.Stop()
			wg.Done()
			log.Println("Stopped certificate event watcher.")
			return
		}
	}
}

func (p *CertProcessor) maintenance(syncInterval time.Duration, wg *sync.WaitGroup, doneChan <-chan struct{}) {
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

func (p *CertProcessor) processCertificateEvent(c CertificateEvent) error {
	switch c.Type {
	case "ADDED", "MODIFIED":
		_, err := p.processCertificate(c.Object, false)
		return err
	}
	return nil
}

func (p *CertProcessor) secretName(cert Certificate) string {
	if cert.Spec.SecretName != "" {
		return cert.Spec.SecretName
	}
	return p.certSecretPrefix + cert.Spec.Domain
}

// normalizeHostnames returns a copy of the hostnames array where all hostnames are lower
// cased and the array sorted.
// This allows the input to have changed order or different casing between runs,
// but a new certificate will only be created if a certificate is added or removed.
func normalizeHostnames(hostnames []string) []string {
	arr := make([]string, len(hostnames))
	copy(arr, hostnames)
	for i, hostname := range arr {
		arr[i] = strings.ToLower(hostname)
	}
	sort.Strings(arr)

	return arr
}

func (p *CertProcessor) getStoredAltNames(cert Certificate) ([]string, error) {
	var altNamesRaw []byte
	err := p.db.View(func(tx *bolt.Tx) error {
		altNamesRaw = tx.Bucket([]byte("domain-altnames")).Get([]byte(cert.Spec.Domain))
		return nil
	})
	if err != nil {
		return nil, errors.Wrapf(err, "Error while fetching altnames from database for domain %v", cert.Spec.Domain)
	}
	if altNamesRaw == nil {
		return nil, nil
	}

	var altNames []string
	err = json.Unmarshal(altNamesRaw, &altNames)
	if err != nil {
		return nil, errors.Wrapf(err, "Error while unmarshalling altnames from database for domain %v", cert.Spec.Domain)
	}
	return altNames, nil
}

func equalAltNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// processCertificate creates or renews the corresponding secret
// processCertificate will create new ACME users if necessary, and complete ACME challenges
// processCertificate caches ACME user and certificate information in boltdb for reuse
func (p *CertProcessor) processCertificate(cert Certificate, forMaint bool) (bool, error) {
	var (
		acmeUserInfo    ACMEUserData
		acmeCertDetails ACMECertDetails
		acmeCert        ACMECertData
		acmeClient      *acme.Client
		acmeClientMutex *sync.Mutex
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

	namespace := certificateNamespace(cert)

	if cert.Status.Provisioned == "false" {
		p.deleteFailedCertIfNeeded(cert, namespace)
		return true, nil
	}

	if cert.Status.Provisioned == "true" && !forMaint {
		// we don't currently support updates to the cert.  Once we're on a newer
		// kube api with support for generation updates, we can do updates.
		return false, nil
	}

	// Fetch current certificate data from k8s
	s, err := p.k8s.getSecret(namespace, p.secretName(cert))
	if err != nil {
		return p.NoteCertError(cert, err, "Error while fetching certificate acme data for domain %v", cert.Spec.Domain)
	}

	// Once MWX is updated this can be turned on.
	// if s != nil && !forMaint && cert.Status.Provisioned == "" {
	// 	return p.NoteCertError(cert, err, "Duplicate cert request for secret %s/%s", namespace, p.secretName(cert))
	// }

	altNames := normalizeHostnames(cert.Spec.AltNames)
	storedAltNames, err := p.getStoredAltNames(cert)
	if err != nil {
		return false, errors.Wrap(err, "Error while getting stored alternative names")
	}

	sameAltNames := equalAltNames(altNames, storedAltNames)

	// If a cert exists, and altNames are correct check its expiry and expected altNames
	if s != nil && getDomainFromLabel(s, p.tagPrefix) == cert.Spec.Domain && sameAltNames {
		acmeCert, err = NewACMECertDataFromSecret(s, p.tagPrefix)
		if err != nil {
			return p.NoteCertError(cert, err, "Error while decoding acme certificate from secret for existing domain %v", cert.Spec.Domain)
		}

		// Decode cert
		pemBlock, _ := pem.Decode(acmeCert.Cert)
		if pemBlock == nil {
			pemError := errors.New("Cannot continue")
			return p.NoteCertError(cert, pemError, "Got nil back when decoding x509 encoded certificate for existing domain %v", cert.Spec.Domain)
		}

		parsedCert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return p.NoteCertError(cert, err, "Error while parsing x509 encoded certificate for existing domain %v", cert.Spec.Domain)
		}

		// If certificate expires after now + p.renewBeforeDays, don't renew
		if parsedCert.NotAfter.After(time.Now().Add(time.Hour * time.Duration(24*p.renewBeforeDays))) {
			// if we've got dup request for already created secret, just return that we're done.
			// once MWX is updated, this can be replaced with the failure logic above.
			if cert.Status.Provisioned == "" {
				log.Printf("[%s] Setting status to reflect the existance of the secret", cert.FQName())
				created, _ := parsedCert.NotBefore.MarshalText()
				expires, _ := parsedCert.NotAfter.MarshalText()

				p.k8s.updateCertStatus(namespace, cert.Metadata.Name, CertificateStatus{
					Provisioned: "true",
					CreatedDate: string(created),
					ExpiresDate: string(expires),
				})
			}
			return false, nil
		}

		log.Printf("[%v] Expiry for cert is in less than %v days (%v), attempting renewal", cert.Spec.Domain, p.renewBeforeDays, parsedCert.NotAfter.String())
	}

	email := valueOrDefault(cert.Spec.Email, p.defaultEmail)

	// Fetch acme user data and cert details from bolt
	var userInfoRaw, certDetailsRaw []byte
	err = p.db.View(func(tx *bolt.Tx) error {
		userInfoRaw = tx.Bucket([]byte("user-info")).Get([]byte(email))
		certDetailsRaw = tx.Bucket([]byte("cert-details")).Get([]byte(cert.Spec.Domain))
		return nil
	})

	if err != nil {
		return p.NoteCertError(cert, err, "Error while running bolt view transaction for domain %v", cert.Spec.Domain)
	}

	provider := valueOrDefault(cert.Spec.Provider, p.defaultProvider)

	// Handle user information
	if userInfoRaw != nil { // Use existing user
		if err = json.Unmarshal(userInfoRaw, &acmeUserInfo); err != nil {
			return p.NoteCertError(cert, err, "Error while unmarshalling user info for %v", cert.Spec.Domain)
		}

		log.Printf("Creating ACME client for existing account %v, domain %v, and provider %v", email, cert.Spec.Domain, provider)
		acmeClient, acmeClientMutex, err = p.newACMEClient(&acmeUserInfo, provider)
		if err != nil {
			return p.NoteCertError(cert, err, "Error while creating ACME client for %v provider for %v", provider, cert.Spec.Domain)
		}

		// Some acme providers require locking, if the mutex is specified, lock it
		if acmeClientMutex != nil {
			acmeClientMutex.Lock()
			defer acmeClientMutex.Unlock()
		}
	} else { // Generate a new ACME user
		userKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return p.NoteCertError(cert, err, "Error while generating rsa key for new user for domain %v", cert.Spec.Domain)
		}

		acmeUserInfo.Email = email
		acmeUserInfo.Key = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(userKey),
		})

		log.Printf("Creating new ACME client for new account %v, domain %v, and provider %v", email, cert.Spec.Domain, provider)
		acmeClient, acmeClientMutex, err = p.newACMEClient(&acmeUserInfo, provider)
		if err != nil {
			return p.NoteCertError(cert, err, "Error while creating ACME client for %v", cert.Spec.Domain)
		}

		// Some acme providers require locking, if the mutex is specified, lock it
		if acmeClientMutex != nil {
			acmeClientMutex.Lock()
			defer acmeClientMutex.Unlock()
		}

		// Register
		acmeUserInfo.Registration, err = acmeClient.Register()
		if err != nil {
			return p.NoteCertError(cert, err, "Error while registering user for new domain %v", cert.Spec.Domain)
		}

		// Agree to TOS
		if err := acmeClient.AgreeToTOS(); err != nil {
			return p.NoteCertError(cert, err, "Error while agreeing to acme TOS for new domain %v", cert.Spec.Domain)
		}

		userInfoRaw, err = json.Marshal(&acmeUserInfo)
		if err != nil {
			return p.NoteCertError(cert, err, "Error while marshalling user info for domain %v", cert.Spec.Domain)
		}

		// Save user info to bolt
		err = p.db.Update(func(tx *bolt.Tx) error {
			key := []byte(email)
			tx.Bucket([]byte("user-info")).Put(key, userInfoRaw)
			return nil
		})

		if err != nil {
			return p.NoteCertError(cert, err, "Error while saving user data to bolt for domain %v", cert.Spec.Domain)
		}
	}

	domains := append([]string{cert.Spec.Domain}, altNames...)
	// If we have cert details stored with expected altNames, do a renewal, otherwise, obtain from scratch
	if certDetailsRaw == nil || acmeCert.DomainName == "" || !sameAltNames {
		acmeCert.DomainName = cert.Spec.Domain

		// Obtain a cert
		certRes, errs := acmeClient.ObtainCertificate(domains, true, nil, false)
		for _, domain := range domains {
			if errs[domain] != nil {
				return p.NoteCertError(cert, errs[domain], "Error while obtaining certificate for new domain %v", domain)
			}
		}

		// fill in data
		acmeCert.Cert = certRes.Certificate
		acmeCert.PrivateKey = certRes.PrivateKey
		acmeCertDetails = NewACMECertDetailsFromResource(certRes)
	} else {
		if err := json.Unmarshal(certDetailsRaw, &acmeCertDetails); err != nil {
			return p.NoteCertError(cert, err, "Error while unmarshalling cert details for existing domain %v", cert.Spec.Domain)
		}

		// Fill in cert resource
		certRes := acmeCertDetails.ToCertResource()
		certRes.Certificate = acmeCert.Cert
		certRes.PrivateKey = acmeCert.PrivateKey

		certRes, err = acmeClient.RenewCertificate(certRes, true, false)
		if err != nil {
			return p.NoteCertError(cert, err, "Error while renewing certificate for existing domain %v", cert.Spec.Domain)
		}

		// Fill in details
		acmeCert.Cert = certRes.Certificate
		acmeCert.PrivateKey = certRes.PrivateKey
		acmeCertDetails = NewACMECertDetailsFromResource(certRes)
	}

	// Serialize acmeCertDetails and acmeUserInfo
	certDetailsRaw, err = json.Marshal(&acmeCertDetails)
	if err != nil {
		return p.NoteCertError(cert, err, "Error while marshalling cert details for domain %v", cert.Spec.Domain)
	}

	altNamesRaw, err := json.Marshal(altNames)
	if err != nil {
		return p.NoteCertError(cert, err, "Error while marshalling altNames for domain %v", cert.Spec.Domain)
	}

	// Save cert details to bolt
	err = p.db.Update(func(tx *bolt.Tx) error {
		key := []byte(cert.Spec.Domain)
		tx.Bucket([]byte("cert-details")).Put(key, certDetailsRaw)
		tx.Bucket([]byte("domain-altnames")).Put(key, altNamesRaw)
		return nil
	})
	if err != nil {
		return p.NoteCertError(cert, err, "Error while saving data to bolt for domain %v", cert.Spec.Domain)
	}

	// Convert cert data to k8s secret
	isUpdate := s != nil
	s = acmeCert.ToSecret(p.secretName(cert), cert.Metadata.Labels)

	if isUpdate {
		log.Printf("Updating secret %v in namespace %v for domain %v", s.Name, namespace, cert.Spec.Domain)
	} else {
		log.Printf("Creating secret %v in namespace %v for domain %v", s.Name, namespace, cert.Spec.Domain)
	}

	// Save the k8s secret
	if err := p.k8s.saveSecret(namespace, s, isUpdate); err != nil {
		return p.NoteCertError(cert, err, "Error while saving secret for domain %v", cert.Spec.Domain)
	}

	msg := "Created certificate"
	if isUpdate {
		msg = "Updated certificate"
	}
	p.k8s.createEvent(v1.Event{
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
	exp, _ := acmeCert.ExpiresDate().MarshalText()

	p.k8s.updateCertStatus(namespace, cert.Metadata.Name, CertificateStatus{
		Provisioned: "true",
		CreatedDate: string(now),
		ExpiresDate: string(exp),
	})

	return true, nil
}

func (p *CertProcessor) NoteCertError(cert Certificate, err error, format string, args ...interface{}) (bool, error) {
	namespace := certificateNamespace(cert)
	wrapped_err := errors.Wrapf(err, format, args)
	now, _ := time.Now().UTC().MarshalText()

	p.k8s.updateCertStatus(namespace, cert.Metadata.Name, CertificateStatus{
		Provisioned: "false",
		ErrorDate:   string(now),
		ErrorMsg:    wrapped_err.Error(),
	})

	return false, wrapped_err
}

func certificateNamespace(c Certificate) string {
	if c.Metadata.Namespace != "" {
		return c.Metadata.Namespace
	}
	return "default"
}

func valueOrDefault(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (p *CertProcessor) deleteFailedCertIfNeeded(c Certificate, namespace string) {
	cutoff := c.Metadata.CreationTimestamp.Time.UTC().AddDate(0, 0, 7)

	if cutoff.Before(time.Now().UTC()) {
		err := p.k8s.deleteCertificate(c, namespace)
		if err != nil {
			log.Printf("Error deleting cert %s with error %s", c.Metadata.Name, err)
		}
	}
}
