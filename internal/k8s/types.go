package k8s

import (
	"crypto/sha256"
	"encoding/json"
	"strings"

	"github.com/liquidweb/kube-cert-manager/internal/util"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/api/meta"
	"k8s.io/client-go/pkg/api/unversioned"
	"k8s.io/client-go/rest"
)

// K8sClient provides convenience functions for handling resources this project
// cares about
// TODO: merge the two clients
type K8sClient struct {
	c          *kubernetes.Clientset
	certClient *rest.RESTClient
}

func NewK8sClient(c *kubernetes.Clientset, certClient *rest.RESTClient) K8sClient {
	return K8sClient{
		c:          c,
		certClient: certClient,
	}
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
	Metadata             api.ObjectMeta    `json:"metadata"`
	Spec                 CertificateSpec   `json:"spec"`
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

func (c *Certificate) FQName() string {
	return c.Metadata.Namespace + "/" + c.Metadata.Name
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
	Challange  string   `json:"challange"`
	CA         string   `json:"ca"`
	Email      string   `json:"email"`
	SecretName string   `json:"secretName"`
	AltNames   []string `json:"altNames"`
}

func (c *Certificate) Checksum() []byte {
	h := sha256.New()

	lower := strings.ToLower(c.Spec.Domain)

	h.Write([]byte(lower))

	names := util.NormalizedAltNames(c.Spec.AltNames)
	for _, name := range names {
		h.Write([]byte(name))
	}

	return h.Sum(nil)
}

func (c *Certificate) HasSANs() bool {
	return len(c.Spec.AltNames) > 0
}
