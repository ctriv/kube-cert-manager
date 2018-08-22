package processor

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/boltdb/bolt"
	"github.com/gammazero/workerpool"
	"github.com/liquidweb/kube-cert-manager/internal/k8s"
	"github.com/liquidweb/kube-cert-manager/internal/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/vburenin/nsync"
	"k8s.io/client-go/pkg/api"
)

func TestProcessCertEarlyExits(t *testing.T) {
	p, meta := getTestProcessor()
	defer meta.finish()

	cert := k8s.Certificate{
		Metadata: api.ObjectMeta{
			Name:      "test",
			Namespace: "test",
		},
		Spec: k8s.CertificateSpec{
			Domain:     "epcot.org",
			SecretName: "some-secret",
		},
		Status: k8s.CertificateStatus{
			Provisioned: "false",
		},
	}

	_, err := p.processCertificate(cert, true)
	assertKubeNeverCalled(t, meta)
	assertCANeverCalled(t, meta)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	cert = k8s.Certificate{
		Metadata: api.ObjectMeta{
			Name:      "test",
			Namespace: "test",
		},
		Spec: k8s.CertificateSpec{
			Domain:     "epcot.org",
			SecretName: "some-secret",
		},
		Status: k8s.CertificateStatus{
			Provisioned: "true",
		},
	}
	_, err = p.processCertificate(cert, false)
	assertKubeNeverCalled(t, meta)
	assertCANeverCalled(t, meta)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	cert = k8s.Certificate{
		Metadata: api.ObjectMeta{
			Name:      "test",
			Namespace: "test",
		},
		Spec: k8s.CertificateSpec{
			Domain:     "epcot.org",
			SecretName: "",
		},
	}
	meta.k8s.On("UpdateCertStatus", "test", "test", mock.AnythingOfType("k8s.CertificateStatus")).Return(nil)
	_, err = p.processCertificate(cert, false)
	assertCANeverCalled(t, meta)
	if err == nil {
		t.Error("Did not get an error when processing a cert without a secret name")
	}
}

type testProcessorMeta struct {
	finish func()
	k8s    *mocks.KubeAdapter
	ca     *mocks.CertificateAuthority
}

func assertKubeNeverCalled(t *testing.T, meta testProcessorMeta) {
	methods := []string{
		"GetSecret", "SaveSecret", "UpdateCertStatus", "UpdateCertSpec",
		"CreateEvent", "DeleteCertificate", "DeleteSecret", "GetSecrets",
		"GetCertificates", "MonitorCertificateEvents",
	}
	for _, method := range methods {
		meta.k8s.AssertNotCalled(t, method)
	}
}

func assertCANeverCalled(t *testing.T, meta testProcessorMeta) {
	methods := []string{
		"ProvisionCert", "RenewCert", "SetupRoute",
	}

	for _, method := range methods {
		meta.ca.AssertNotCalled(t, method)
	}
}

func getTestProcessor() (*CertProcessor, testProcessorMeta) {
	tmpfile, err := ioutil.TempFile("", "example")
	if err != nil {
		log.Fatal(err)
	}

	meta := testProcessorMeta{
		finish: func() {
			os.Remove(tmpfile.Name())
		},
		k8s: &mocks.KubeAdapter{},
		ca:  &mocks.CertificateAuthority{},
	}

	db, err := bolt.Open(tmpfile.Name(), 0600, nil)
	if err != nil {
		meta.finish()
		log.Fatal(err)
	}

	p := CertProcessor{
		k8s:              meta.k8s,
		acmeURL:          "http://testing/",
		Namespaces:       nil,
		defaultChallange: "http",
		defaultCA:        "testing",
		defaultEmail:     "testing@liquidweb.com",
		db:               db,
		renewBeforeDays:  15,
		wp:               workerpool.New(1),
		maintWp:          workerpool.New(1),
		locks:            nsync.NewNamedMutex(),
		CAs: map[string]CertificateAuthority{
			"testing": meta.ca,
		},
	}

	return &p, meta

}
