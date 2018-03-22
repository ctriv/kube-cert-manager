import (
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

    "crypto/rand"
    "crypto/rsa"
)

type AcmeCertAuthority struct {
    processor *CertProcessor
}

type ACMEUserData struct {
    Email        string                     `json:"email"`
    Registration *acme.RegistrationResource `json:"registration"`
    Key          []byte                     `json:"key"`
}


func (ca *AcmeCertAuthority) ProvisionCert(cert *Certificate) (CertData, error) {
    acmeClient, mutex, err := ca.Init(cert)

    if err == nil {
        return nil, err
    }

    certRes, errs := acmeClient.ObtainCertificate(domains, true, nil, false)

    for _, domain := range domains {
        if errs[domain] != nil {
            return nil, return errors.Wrapf(errs[domain], "Error while obtaining certificate for new domain %v", domain)
        }
    }

    ret := CertData{
        DomainName: cert.Spec.Domain,
        AltNames:   cert.Spec.AltNames,
        Cert:       certRes.Certificate,
        PrivateKey: certRes.PrivateKey,
        CAExtras:   map[string]string{
            "CertStableURL": certRes.CertStableURL,
            "AccountRef":    certRes.AccountRef,
            "CertURL":       certRes.CertURL
        }
    }

    return ret, nil
}

func (ca *AcmeCertAuthority) RenewCert(cert *Certificate, certDetails *CertData) (CertData, error) {
    acmeClient, mutex, err := ca.Init(cert)

    if err != nil {
        return nil, err
    }

    certRes = acme.CertificateResource{
        Domain:        certDetails.DomainName,
        CertURL:       certDetails.CAExtras["CertURL"],
        CertStableURL: certDetails.CAExtras["CertStableURL"],
        AccountRef:    certDetails.CAExtras["AccountRef"]
    }

    certRes, errs := acmeClient.RenewCertificate(certRes, true, false)
    for _, domain := range domains {
        if errs[domain] != nil {
            return nil, errors.Wrapf(errs[domain], "Error while obtaining certificate for new domain %v", domain)
        }
    }

    ret := CertData{
        DomainName: cert.Spec.Domain,
        AltNames:   cert.Spec.AltNames,
        Cert:       certRes.Certificate,
        PrivateKey: certRes.PrivateKey
        CAExtras:   map[string]string{
            "CertStableURL": certRes.CertStableURL,
            "AccountRef":    certRes.AccountRef,
            "CertURL":       certRes.CertURL
        }
    }

    return ret, nil
}

func (ca *AcmeCertAuthority) Init(cert *Certificate) (*acme.Client, *sync.Mutex, error) {
    email := ca.processor.emailForCert(cert)

    err := ca.processor.db.View(func(tx *bolt.Tx) error {
        userInfoRaw = tx.Bucket([]byte("user-info")).Get([]byte(email))
        return nil
    })

    if err != nil {
        return nil, nil, errors.Wrapf(err, "Error pulling cached user info for %s", email)
    }

    if userInfoRaw == nil {
        return ca.CreateNewUser(cert, email)
    }

    if err := json.Unmarshal(userInfoRaw, &acmeUserInfo); err != nil {
        return nil, nil, errors.Wrapf(err, "Error while unmarshalling user info for %v", cert.Spec.Domain)
    }

    log.Printf("Creating ACME client for existing account %v, domain %v, and provider %v", email, cert.Spec.Domain, provider)
    acmeClient, acmeClientMutex, err = ca.newACMEClient(&acmeUserInfo, provider)

    if err != nil {
        return nil, nil, err
    }

    return acmeClient, acmeClientMutex, nil
}

func (ca *AcmeCertAuthority) CreateNewUser(cert Certificate, email string) (*ACMEUserData, *acme.Client, *sync.Mutex, error) {
    userKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return errors.Wrapf(err, "Error while generating rsa key for new user for domain %v", cert.Spec.Domain)
    }

    acmeUserInfo.Email = email
    acmeUserInfo.Key = pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(userKey),
    })

    log.Printf("Creating new ACME client for new account %v, domain %v, and provider %v", email, cert.Spec.Domain, provider)
    acmeClient, acmeClientMutex, err = ca.newACMEClient(&acmeUserInfo, provider)

    if err != nil {
        return nil, nil, errors.Wrapf(err, "Error while creating ACME client for %v", cert.Spec.Domain)
    }

    // Register
    acmeUserInfo.Registration, err = acmeClient.Register()
    if err != nil {
        return nil, nil, errors.Wrapf(err, "Error while registering user for new domain %v", cert.Spec.Domain)
    }

    // Agree to TOS
    if err := acmeClient.AgreeToTOS(); err != nil {
        return nil, nil, errors.Wrapf(err, "Error while agreeing to acme TOS for new domain %v", cert.Spec.Domain)
    }

    userInfoRaw, err = json.Marshal(&acmeUserInfo)
    if err != nil {
        return nil, nil, errors.Wrapf(err, "Error while marshalling user info for domain %v", cert.Spec.Domain)
    }

    // Save user info to bolt
    err = ca.processor.db.Update(func(tx *bolt.Tx) error {
        key := []byte(email)
        tx.Bucket([]byte("user-info")).Put(key, userInfoRaw)
        return nil
    })

    if err != nil {
        return nil, nil, errors.Wrapf(err, "Error while saving user data to bolt for domain %v", cert.Spec.Domain)
    }

    return acmeUserInfo, acmeClient, acmeClientMutex, nil
}

func (ca *AcmeCertAuthority) newACMEClient(acmeUser acme.User, provider string) (*acme.Client, *sync.Mutex, error) {
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
		acmeClient.ExcludeChallenges([]acme.Challenge{acme.DNS01, acme.TLSSNI01})
		return acmeClient, &p.HTTPLock, nil
	case "tls":
		acmeClient.SetTLSAddress(":8081")
		acmeClient.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.DNS01})
		return acmeClient, &p.TLSLock, nil
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
