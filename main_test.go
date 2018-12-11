package main

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	//metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"
	"strings"
	"testing"
)

/*
	Certificate Custom Resource Definition
*/
/*type Certificate struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta `json:"metadata"`
	Spec            CertificateSpec   `json:"spec"`
	Status          CertificateStatus `json:"status,omitempty"`
}

type CertificateStatus struct {
	Provisioned string `json:"provisioned,omitempty"`
	CreatedDate string `json:"created,omitempty"`
	ExpiresDate string `json:"expires,omitempty"`
	ErrorMsg    string `json:"error_msg,omitempty"`
	ErrorDate   string `json:"error_date,omitempty"`
}

type CertificateSpec struct {
	Domain     string   `json:"domain"`
	Provider   string   `json:"provider"`
	Email      string   `json:"email"`
	SecretName string   `json:"secretName"`
	AltNames   []string `json:"altNames"`
}*/

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
	/*result :=

	k8sClient.BatchV1Client.RESTClient().Post().Name("kube-system").Resource("certificate").
		Body(certObj).Do().Into(result)*/

}
