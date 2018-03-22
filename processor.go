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
    "crypto/x509"
    "encoding/json"
    "encoding/pem"
    "log"
    "sort"
    "strings"
    "sync"
    "time"

    "github.com/boltdb/bolt"
    "github.com/pkg/errors"

    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/pkg/api/v1"
    "k8s.io/client-go/rest"


)

// CertProcessor holds the shared configuration, state, and locks
type CertProcessor struct {
    acmeURL          string
    certNamespace    string
    tagPrefix        string
    namespaces       []string
    defaultProvider  string
    defaultEmail     string
    db               *bolt.DB
    Lock             sync.Mutex
    HTTPLock         sync.Mutex
    TLSLock          sync.Mutex
    k8s              K8sClient
    renewBeforeDays  int
}

// NewCertProcessor creates and populates a CertProcessor
func NewCertProcessor(
    k8s *kubernetes.Clientset,
    certClient *rest.RESTClient,
    acmeURL string,
    certNamespace string,
    tagPrefix string,
    namespaces []string,
    defaultProvider string,
    defaultEmail string,
    db *bolt.DB,
    renewBeforeDays int) *CertProcessor {
    return &CertProcessor{
        k8s:              K8sClient{c: k8s, certClient: certClient},
        acmeURL:          acmeURL,
        certNamespace:    certNamespace,
        tagPrefix:        tagPrefix,
        namespaces:       namespaces,
        defaultProvider:  defaultProvider,
        defaultEmail:     defaultEmail,
        db:               db,
        renewBeforeDays:  renewBeforeDays,
    }
}


func (p *CertProcessor) syncCertificates() error {
    p.Lock.Lock()
    defer p.Lock.Unlock()

    certificates, err := p.getCertificates()
    if err != nil {
        return err
    }

    var wg sync.WaitGroup
    for _, cert := range certificates {
        wg.Add(1)
        go func(cert Certificate) {
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

func (p *CertProcessor) maintenance(syncInterval time.Duration, wg *sync.WaitGroup, doneChan <-chan struct{}) {
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

func (p *CertProcessor) processCertificateEvent(c CertificateEvent) error {
    p.Lock.Lock()
    defer p.Lock.Unlock()
    switch c.Type {
    case "ADDED", "MODIFIED":
        _, err := p.processCertificate(c.Object)
        return err
    }
    return nil
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
func (p *CertProcessor) processCertificate(cert Certificate) (processed bool, err error) {
    var certDetails CertData

    if cert.Status.Provisioned == "false" {
        log.Printf("Cert %s/%s has already failed to provision.  Skipping.", cert.Metadata.Namespace, cert.Metadata.Name)
        return true, nil
    }

    if cert.Spec.SecretName == "" {
        return p.NoteCertError(cert, nil, "Secret name not set")
    }

    // Fetch current certificate data from k8s
    s, err := p.k8s.getSecret(cert.Metadata.Namespace, cert.Spec.SecretName)
    if err != nil {
        return p.NoteCertError(cert, err, "Error while fetching secret for domain %v", cert.Spec.Domain)
    }

    secretHasSameNames, certNeedsRenewal, err := p.checkSecretForCert(s, cert)

    if err != nil {
        return p.NoteCertError(cert, err, "Could not examine existing secret for correctness.")
    }

    ca, err := p.caForCert(cert)
    if err != nil {
        return p.NoteCertError(cert, err, "Could not get a CA for domain: %b", cert.Spec.Domain)
    }

    // need to think about what happens when the ca for a cert changes...
    if secretHasSameNames && !certNeedsRenewal {
        return false, nil
    }

    altNames := cert.normalizedAltNames()
    email    := valueOrDefault(cert.Spec.Email, p.defaultEmail)
    provider := valueOrDefault(cert.Spec.Provider, p.defaultProvider)
    domains  := append([]string{cert.Spec.Domain}, altNames...)

    certDetails, certNeedsRenewal, err = p.getCachedCert(cert)

    if err != nil {
        return p.NoteCertError(cert, err, "Couldn't lookup cached data for %v", cert.Spec.Domain)
    }


    if certDetails != nil && certNeedsRenewal {
        certDetails, err = ca.RenewCert(cert)

        if err != nil {
            return p.NoteCertError(cert, err, "Error while renewing cert for new domain %v", cert.Spec.Domain)
        }
    } else if certDetails == nil {
        certDetails, err = ca.ProvisionCert(cert)

        if err != nil {
            return p.NoteCertError(cert, err, "Error while provisioning cert for new domain %v", cert.Spec.Domain)
        }
    }

    err = p.saveCertToCache(cert, certDetails)

    if err != nil {
        return p.NoteCertError(cert, err, "Error while syncing cert for %v to the backing cache", cert.Spec.Domain)
    }

    // Convert cert data to k8s secret
    isUpdate := s != nil
    s = certDetails.ToSecret(cert.Spec.SecretName, cert.Metadata.Labels)

    if isUpdate {
        log.Printf("Updating secret %v in namespace %v for domain %v", s.Name, cert.Metadata.Namespace, cert.Spec.Domain)
    } else {
        log.Printf("Creating secret %v in namespace %v for domain %v", s.Name, cert.Metadata.Namespace, cert.Spec.Domain)
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
            Namespace: cert.Metadata.Namespace,
        },
        InvolvedObject: v1.ObjectReference{
            Kind:      "Secret",
            Namespace: cert.Metadata.Namespace,
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

    p.k8s.updateCertStatus(cert.Metadata.Namespace, cert.Metadata.Name, CertificateStatus{
        Provisioned: "true",
        CreatedDate: string(now),
        ExpiresDate: string(exp),
    })

    return true, nil
}

func (p *CertProcessor) saveCertToCache(cert Certificate, certDetails CertData) error {
    // Serialize acmeCertDetails and acmeUserInfo
    certDetailsRaw, err = json.Marshal(&certDetails)
    if err != nil {
        return errors.Wrapf(err, "Error while marshalling cert details for domain %v", cert.Spec.Domain)
    }

    altNamesRaw, err := json.Marshal(altNames)
    if err != nil {
        return errors.Wrapf(err, "Error while marshalling altNames for domain %v", cert.Spec.Domain)
    }

    // Save cert details to bolt
    err = p.db.Update(func(tx *bolt.Tx) error {
        key := cert.DbKey()
        tx.Bucket([]byte("cert-details")).Put(key, certDetailsRaw)
        tx.Bucket([]byte("domain-altnames")).Put(key, altNamesRaw)
        return nil
    })

    if err != nil {
        return errors.Wrapf(err, "Error while saving data to bolt for domain %v", cert.Spec.Domain)
    }

    return nil
}

func (p *CertProcessor) checkSecretForCert(s *v1.Secret, cert Certificate) (bool, bool, error) {
    altNames := normalizeHostnames(cert.Spec.AltNames)
    storedAltNames, err := p.getStoredAltNames(cert)
    if err != nil {
        return nil, nil, errors.Wrapf(err, "Error while getting stored alternative names")
    }

    sameAltNames := equalAltNames(altNames, storedAltNames)

    // If a cert exists and altNames are correct, check its expiry and expected altNames
    // then if everything lines up, perform a renewal.
    if s != nil && getDomainFromLabel(s, p.tagPrefix) == cert.Spec.Domain && sameAltNames {
        certdata, err = CertDataFromSecret(s, p.tagPrefix)
        if err != nil {
            return nil, nil, errors.Wrapf(err, "Error while decoding certificate from secret for existing domain %v", cert.Spec.Domain)
        }

        // Decode cert
        pemBlock, _ := pem.Decode(certdata.Cert)
        if pemBlock == nil {
            return nil, nil, errors.Wrapf(err, "Got nil back when decoding x509 encoded certificate for existing domain %v", cert.Spec.Domain)
        }

        parsedCert, err := x509.ParseCertificate(pemBlock.Bytes)
        if err != nil {
            return nil, nil, errors.Wrapf(err, "Error while parsing x509 encoded certificate for existing domain %v", cert.Spec.Domain)
        }

        // If certificate expires after now + p.renewBeforeDays, don't renew
        if parsedCert.NotAfter.After(time.Now().Add(time.Hour * time.Duration(24*p.renewBeforeDays))) {
            return true, false, nil
        }

        log.Printf("[%v] Expiry for cert is in less than %v days (%v), attempting renewal", cert.Spec.Domain, p.renewBeforeDays, parsedCert.NotAfter.String())
        return true, false, nil
    }
}

func (p *CertProcessor) getCachedCert(cert Certificate) (Certificate, error) {
    // Fetch acme user data and cert details from bolt
    var cachedCertDetails []byte
    err = p.db.View(func(tx *bolt.Tx) error {
        cachedCertDetails = tx.Bucket([]byte("cert-details")).Get([]byte(cert.Spec.Domain))
        return nil
    })

    if err != nil {
        return p.NoteCertError(cert, err, "Error while running bolt view transaction for domain %v", cert.Spec.Domain)
    }

}


func (p *CertProcessor) NoteCertError(cert Certificate, err error, format string, args ...interface{}) (bool, error) {
    namespace   := cert.Metadata.Namespace
    wrapped_err := errors.Wrapf(err, format, args)
    now, _ := time.Now().UTC().MarshalText()

    p.k8s.updateCertStatus(namespace, cert.Metadata.Name, CertificateStatus{
        Provisioned: "false",
        ErrorDate: string(now),
        ErrorMsg: wrapped_err.Error(),
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
    certs, err := p.getCertificates()
    if err != nil {
        return err
    }
    usedSecrets := map[string]bool{}
    for _, cert := range certs {
        usedSecrets[cert.Metadata.Namespace+" "+p.Spec.SecretName] = true
    }
    for _, secret := range secrets {
        if usedSecrets[secret.Namespace+" "+secret.Name] {
            continue
        }
        // need to replace to to use an annotation to mark the secret as from us
        log.Printf("Deleting unused secret %s in namespace %s", secret.Name, secret.Namespace)
        if err := p.k8s.deleteSecret(secret.Namespace, secret.Name); err != nil {
            return err
        }
    }
    return nil
}

func (p *CertProcessor) caForCert(cert Certificate) (CertificateAuthority, error) {
    ca := valueOrDefault(cer.CA, p.defaultCA)

    switch valueOrDefault(cert.CA, p.defaultCA) {
    case "letsencrypt":
        return AcmeCertAuthority{"processor": p}, nil
    case "globalsign":
        return GlobalSignCertAuthority{"processor": p}, nil
    default:
        return nil, fmt.Errorf("Unknown cert authority: %s", ca)
    }
}

func valueOrDefault(a, b string) string {
    if a != "" {
        return a
    }
    return b
}
