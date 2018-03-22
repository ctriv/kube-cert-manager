package main

import (
    "crypto/x509"
    "encoding/json"
    "encoding/pem"
    "log"
    "time"

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
    ErrorMsg    string `json:"error_msg,omitempty"`
    ErrorDate   string `json:"error_date,omitempty"`
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
    CA         string   `json:"ca"`
    Email      string   `json:"email"`
    SecretName string   `json:"secretName"`
    AltNames   []string `json:"altNames"`
}



type CertData struct {
    DomainName  string
    AltNames   []string
    Cert       []byte
    PrivateKey []byte
    CAExtras   map[string]string
}

type CertificateAuthority interface {
    ProvisionCert(*Certificate) (CertData, error)
    RenewCert(*Certificate, *CertData) (CertData, error)
}

func (c *Certificate) normalizedAltNames() []string {
    arr := make([]string, len(c.Spec.AltNames))
    copy(arr, c.Spec.AltNames)
    for i, hostname := range arr {
        arr[i] = strings.ToLower(c.Spec.AltNames)
    }
    sort.Strings(arr)

    return arr
}

// ToSecret creates a Kubernetes Secret from an ACME Certificate
func (c *CertData) ToSecret(name string, labels map[string]string) *v1.Secret {
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

func (c *CertData) ExpiresDate() time.Time {
    block, _ := pem.Decode(c.Cert)

    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        log.Printf("Error while parsing cert expiration date: %s", err)
    }


    return cert.NotAfter
}
