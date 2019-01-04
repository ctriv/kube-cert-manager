package main

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"math/rand"
	"os"
	"testing"
	"time"
)

var SchemeGroupVersion = schema.GroupVersion{Group: "stable.liquidweb.com", Version: "v1"}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestIntegrationDBConnection(t *testing.T) {
	log.Println("Testing DB Connection")

	var conf Conf
	conf.GetConf()

	if conf.LogFile != "" {
		f, err := os.OpenFile(conf.LogFile, os.O_WRONLY|os.O_CREATE, 0755)
		if err != nil {
			log.Fatalf("Error while reading in file: %v", err)
		}
		log.SetOutput(f)
	}

	db := db(conf.Psql.Host, conf.Psql.Port, conf.Psql.User, conf.Psql.DatabaseName, conf.Psql.Password, conf.Psql.SslMode)

	assert.NotNil(t, db, "Database should not be nil")
	db.Close()
}

func TestIntegrationCertCreation(t *testing.T) {
	log.Println("Start create certificate test")

	var conf Conf
	conf.GetConf()

	if conf.LogFile != "" {
		f, err := os.OpenFile(conf.LogFile, os.O_WRONLY|os.O_CREATE, 0755)
		if err != nil {
			log.Fatalf("Error while reading in file: %v", err)
		}
		log.SetOutput(f)
	}

	if conf.Kube.SourceConfigFile == "" {
		log.Fatal("No Kube Config file specified.")
	}

	client := buildClients(conf.Kube.SourceConfigFile)
	testCert := createDummyCert(client, conf)
	provisioned := checkCertStatus(client, testCert.Metadata.Name, conf)
	assert.Equal(t, true, provisioned, "Cert has not provisioned")
	cleanUpCert(client, testCert, conf)
}

func createDummyCert(client K8sClient, conf Conf) Certificate {
	ranNumber := getRandomNumber()
	name := fmt.Sprintf("integration-test-%d", ranNumber)
	domain := fmt.Sprintf("www.integration-test-%d.com", ranNumber)
	secret := fmt.Sprintf("integration-secret-%d", ranNumber)
	alt := fmt.Sprintf("www.integration-alt-%d.com", ranNumber)

	log.Printf("Creating test certificate - %s", name)
	dummyCert := Certificate{
		Metadata: metav1.ObjectMeta{
			Name: name,
		},
		Spec: CertificateSpec{
			Domain:     domain,
			Provider:   "http",
			Email:      "integration-test@liquidweb.com",
			SecretName: secret,
			AltNames:   []string{alt},
		},
		Status: CertificateStatus{},
	}
	_, err := createCertificate(client.certClient, conf.Kube.NameSpace, &dummyCert)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	return dummyCert
}

func checkCertStatus(client K8sClient, certName string, conf Conf) bool {
	log.Printf("Checking certificate status of %s", certName)

	var cert Certificate
	prov := false
	waitCtr := 0

	for waitCtr < 5 || len(cert.Status.Provisioned) == 0 {
		req := client.certClient.Get().Resource("certificates").
			Namespace(conf.Kube.NameSpace).Name(certName)
		err := req.Do().Into(&cert)

		if err != nil {
			log.Printf("Error while retrieving certificate: %v. Retrying", err)
		}

		time.Sleep(2 * time.Second)
		waitCtr = waitCtr + 1
	}

	if cert.Status.Provisioned == "true" {
		prov = true
	}

	return prov
}

func cleanUpCert(client K8sClient, testCert Certificate, conf Conf) {
	log.Printf("Deleting test certificate %s", testCert.Metadata.Name)

	req := client.certClient.Delete().Resource("certificates").
		Namespace(conf.Kube.NameSpace).Name(testCert.Metadata.Name).Do()

	if req.Error() != nil {
		log.Printf("Error while deleting certificate: %v.", req.Error())
	}

	log.Printf("Deleting test secret %s", testCert.Spec.SecretName)

	err := client.c.CoreV1().Secrets("default").Delete(testCert.Spec.SecretName, nil)

	if err != nil {
		log.Printf("Error while deleting secret: %v.", err)
	}
}

func getRandomNumber() int {
	return rand.Intn(1000)
}

func buildClients(configFile string) K8sClient {
	var client K8sClient
	var err error

	client.KubeConfig, err = clientcmd.BuildConfigFromFlags("", configFile)

	if err != nil {
		log.Fatalf("Failed to load client config: %+v", err)
	}

	client.c, err = kubernetes.NewForConfig(client.KubeConfig)
	if err != nil {
		log.Fatalf("Failed to create kubernetes client: %+v", err)
	}

	client.certClient, err = newCertClient(client.KubeConfig)
	if err != nil {
		log.Fatalf("Failed to create certificate client: %+v", err)
	}

	return client
}

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&Certificate{},
		&CertificateList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

func newCertClient(cfg *rest.Config) (*rest.RESTClient, error) {
	scheme := runtime.NewScheme()
	SchemeBuilder := runtime.NewSchemeBuilder(addKnownTypes)
	if err := SchemeBuilder.AddToScheme(scheme); err != nil {
		return nil, err
	}
	config := *cfg
	config.GroupVersion = &SchemeGroupVersion
	config.APIPath = "/apis"
	config.ContentType = runtime.ContentTypeJSON
	config.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: serializer.NewCodecFactory(scheme)}
	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func createCertificate(certClient *rest.RESTClient, namespace string, obj *Certificate) (*Certificate, error) {
	result := &Certificate{}
	err := certClient.Post().
		Namespace(namespace).Resource("certificates").
		Body(obj).Do().Into(result)
	return result, err
}
