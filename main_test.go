package main

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/api/unversioned"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"strings"
	"testing"
)

type SimpleCert struct {
	apiVersion string
	kind       string
	metadata   MetaData
	spec       Spec
}

type MetaData struct {
	name string
}

type Spec struct {
	domain     string
	altNames   []string
	email      string
	provider   string
	secretName string
}

func TestUnitExample(t *testing.T) {
	//Test example
	fmt.Println("Unit test 1")
	actual := strings.ToUpper("hello")
	expected := "HELLO"

	assert.Equal(t, expected, actual)
}

func TestIntegrationDBConnection(t *testing.T) {
	fmt.Println("Testing DB Connection")
	db := db("localhost", "5432", "certmanager", "certmanager", "Pass1234", "disable")

	assert.NotNil(t, db)
	db.Close()
}

func TestIntegrationCertCreate(t *testing.T) {
	fmt.Println("Testing Cert create")
	kubeconfig := "/Users/armandoalvarado/.kube/config"
	var k8sConfig *rest.Config
	var err error
	if kubeconfig == "" {
		k8sConfig, err = rest.InClusterConfig()
	} else {
		k8sConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if err != nil {
		log.Fatalf("Error trying to configure k8s client: %v", err)
	}
	k8sClient, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		log.Fatalf("Error trying to to create k8s client: %v", err)
	}

	assert.NotNil(t, k8sClient)
	result := &Certificate{}
	/*result := &Certificate{}
	meta := MetaData{
		"cert-test-058",
	}
	spec := Spec{
		"www.test.-058.com",
		[]string{"www.alt-name-1-058.com", "www.alt-name-2-058.com"},
		"aalvarado@liquidweb.com",
		"http",
		"cert-test-one-tls-058",
	}
	cert := SimpleCert{
		"stable.liquidweb.com/v1",
		"Certificate",
		meta,
		spec,
	}*/

	///apis/stable.liquidweb.com/v1/namespaces/default/certificates/cert-test-58
	//time := time2.Now()
	time := unversioned.Now()
	objMeta := api.ObjectMeta{
		"cert-test-058",
		"",
		"default",
		"",
		"",
		"",
		0,
		time,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		"",
	}
	typeMeta := unversioned.TypeMeta{
		"",
		"",
	}
	specData := CertificateSpec{
		"www.test-058.com",
		"http",
		"aalvarado@liquidweb.com",
		"cert-test-one-tls-58",
		[]string{"www.alt-name-1-058.com", "www.alt-name-2-058.com"},
	}
	status := CertificateStatus{
		"",
		"",
		"",
		"",
		"",
	}
	cert := Certificate{
		typeMeta,
		objMeta,
		specData,
		status,
	}

	fmt.Print(cert)
	k8sClient.BatchV1Client.RESTClient().Post().Name("default").Resource("certificate").
		Body(cert).Do().Into(result)
	fmt.Printf("this is the result %s", result)

	//req := k8sClient.BatchV1Client.RESTClient().Get().Resource("certificates").Namespace("default")

	req := k8sClient.BatchV1().RESTClient().Get().Resource("certificates").Namespace("default")
	var certList CertificateList

	err = req.Do().Into(&certList)

	if err != nil {
		log.Printf("Error while retrieving certificate: %v. Retrying", err)
	} else {
		fmt.Print(certList.Items)
	}

}
