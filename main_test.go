package main

import (
	"fmt"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"os"
	"strings"
	"testing"
)

var SchemeGroupVersion = schema.GroupVersion{Group: "stable.liquidweb.com", Version: "v1"}

/**
This kubernetes client is a bit different than the one in types.go K8sClient.
This version is used mainly for integration testing. Yet in the future we may
want to refactor to only use one Kubernetes Client for all communication.
*/
type KubeClient struct {
	KubeConfig *rest.Config
	Client     *kubernetes.Clientset
	CertClient *rest.RESTClient
}

type Conf struct {
	LogFile string `mapstructure:"log_file"`

	Psql struct {
		Host         string `mapstructure:"host"`
		Port         int    `mapstructure:"port"`
		DatabaseName string `mapstructure:"db_name"`
		User         string `mapstructure:"user"`
		Password     string `mapstructure:"password"`
		SslMode      string `mapstructure:"ssl_mode"`
	}

	Kube struct {
		SourceConfigFile string `mapstructure:"src_config_file"`
	}
}

func (conf *Conf) GetConf() *Conf {
	viper.AddConfigPath(".")
	viper.SetConfigName("test-conf")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Fatal error config file: %s", err)
	}

	err = viper.Unmarshal(&conf)
	if err != nil {
		log.Fatal("Unable to unmarshal config")
	}

	return conf
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

func TestIntegrationCertCreation(t *testing.T) {
	fmt.Println("Testing cert creation")

	viper.AddConfigPath(".")
	viper.SetConfigName("test-conf.yaml")

	var conf Conf
	conf.GetConf()

	if conf.LogFile != "" {
		f, err := os.OpenFile(conf.LogFile, os.O_WRONLY|os.O_CREATE, 0755)
		if err != nil {
			log.Fatalf("Error while reading in file: %v", err)
		}
		log.SetOutput(f)
	}

	/*createDummyCert(conf)
	provisioned := checkCertStatus(conf)

	assert.Equal(t, true, provisioned, "Cert has not provisioned")*/

	cleanUpCert(conf)

}

func buildClients(configFile string) KubeClient {
	var client KubeClient
	var err error

	fmt.Println(configFile)
	client.KubeConfig, err = clientcmd.BuildConfigFromFlags("", configFile)

	if err != nil {
		log.Fatalf("Failed to load client config: %+v", err)
	}

	client.Client, err = kubernetes.NewForConfig(client.KubeConfig)
	if err != nil {
		log.Fatalf("Failed to create kubernetes client: %+v", err)
	}

	client.CertClient, err = newCertClient(client.KubeConfig)
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

func createDummyCert(conf Conf) {
	if conf.Kube.SourceConfigFile == "" {
		log.Fatal("No Kube Config file specified.")
	}

	client := buildClients(conf.Kube.SourceConfigFile)

	dummyCert := Certificate{
		Metadata: metav1.ObjectMeta{
			Name: "dummy-certobj1",
		},
		Spec: CertificateSpec{
			Domain:     "www.dummy-certificate-1.com",
			Provider:   "http",
			Email:      "aalvarado1@liquidweb.com",
			SecretName: "dummy-certobj-tls-1",
			AltNames:   []string{"dummy-certificate-1.com"},
		},
		Status: CertificateStatus{},
	}
	_, err := createCertificate(client.CertClient, "default", &dummyCert)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

}

func checkCertStatus(conf Conf) bool {
	if conf.Kube.SourceConfigFile == "" {
		log.Fatal("No Kube Config file specified.")
	}

	client := buildClients(conf.Kube.SourceConfigFile)

	req := client.CertClient.Get().Resource("certificates").
		Namespace("default").Name("cert-test-57")

	var cert Certificate

	err := req.Do().Into(&cert)

	if err != nil {
		log.Printf("Error while retrieving certificate: %v. Retrying", err)
	}

	var prov bool
	if cert.Status.Provisioned == "true" {
		prov = true
	} else {
		prov = false
	}

	return prov
}

func cleanUpCert(conf Conf) {
	if conf.Kube.SourceConfigFile == "" {
		log.Fatal("No Kube Config file specified.")
	}

	client := buildClients(conf.Kube.SourceConfigFile)

	req := client.CertClient.Delete().Resource("certificates").
		Namespace("default").Name("cert-test-55").Do()

	if req.Error() != nil {
		log.Printf("Error while deleting certificate: %v.", req.Error())
	}

	err := client.Client.CoreV1().Secrets("default").Delete("cert-test-one-tls-55", nil)

	if err != nil {
		log.Printf("Error while deleting secret: %v.", err)
	}

}
