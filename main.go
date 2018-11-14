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
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/api/unversioned"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/runtime"
	"k8s.io/client-go/pkg/runtime/serializer"
	"k8s.io/client-go/pkg/watch/versioned"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type listFlag []string

func (lf *listFlag) String() string {
	return strings.Join([]string(*lf), ",")
}

func (lf *listFlag) Set(s string) error {
	if len(s) == 0 {
		*lf = []string{}
		return nil
	}
	*lf = strings.Split(s, ",")
	return nil
}

func main() {
	// Parse command line
	var (
		kubeconfig       string
		acmeURL          string
		syncInterval     int
		certSecretPrefix string
		certNamespace    string
		tagPrefix        string
		namespaces       []string
		defaultProvider  string
		defaultEmail     string
		renewBeforeDays  int
		workers          int
		dbHost           string
		dbPort           string
		dbUser           string
		dbName           string
		dbPassword       string
		dbSslMode        string
	)

	flag.StringVar(&kubeconfig, "kubeconfig", "", "The kubeconfig to use; if empty the in-cluster config will be used")
	flag.StringVar(&acmeURL, "acme-url", "", "The URL to the acme directory to use")
	flag.StringVar(&certSecretPrefix, "cert-secret-prefix", "", "The prefix to use for certificate secrets")
	flag.IntVar(&syncInterval, "sync-interval", 300, "Sync interval in seconds")
	flag.StringVar(&certNamespace, "cert-namespace", "stable.liquidweb.com", "Namespace for the Certificate Third Party Resource")
	flag.StringVar(&tagPrefix, "tag-prefix", "stable.liquidweb.com/kcm.", "Prefix added to labels and annotations")
	flag.Var((*listFlag)(&namespaces), "namespaces", "Comma-separated list of namespaces to monitor. The empty list means all namespaces")
	flag.StringVar(&defaultProvider, "default-provider", "", "Default handler to handle ACME challenges")
	flag.StringVar(&defaultEmail, "default-email", "", "Default email address for ACME registrations")
	flag.IntVar(&renewBeforeDays, "renew-before-days", 7, "Renew certificates before this number of days until expiry")
	flag.IntVar(&workers, "workers", 4, "Number of parallel jobs to run at once")
	flag.StringVar(&dbHost, "db-host", "localhost", "hostname of db")
	flag.StringVar(&dbPort, "db-port", "5432", "port number of db")
	flag.StringVar(&dbUser, "db-username", "certmanager", "username for db")
	flag.StringVar(&dbName, "db-name", "certmanager", "name of db")
	flag.StringVar(&dbPassword, "db-password", "Pass1234", "password for db")
	flag.StringVar(&dbSslMode, "db-sslmode", "disable", "enable or disable ssl mode for db connection")
	flag.Parse()

	if acmeURL == "" {
		log.Fatal("The acme-url command line parameter must be specified")
	}

	log.Println("Starting Kubernetes Certificate Controller...")

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

	groupVersion := unversioned.GroupVersion{
		Group:   "stable.liquidweb.com",
		Version: "v1",
	}
	// Create a client for the certificate TPR too
	schemeBuilder := runtime.NewSchemeBuilder(
		func(scheme *runtime.Scheme) error {
			scheme.AddKnownTypes(
				groupVersion,
				&Certificate{},
				&CertificateList{},
				&api.ListOptions{},
				&api.DeleteOptions{},
			)
			versioned.AddToGroupVersion(scheme, groupVersion)
			return nil
		})
	if err := schemeBuilder.AddToScheme(api.Scheme); err != nil {
		log.Fatalf("error setting up certificate scheme: %v", err)
	}

	tprConfig := *k8sConfig
	tprConfig.GroupVersion = &groupVersion
	tprConfig.APIPath = "/apis"
	tprConfig.ContentType = runtime.ContentTypeJSON
	tprConfig.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: api.Codecs}

	certClient, err := rest.RESTClientFor(&tprConfig)
	if err != nil {
		log.Fatalf("error creating TPR Certificate client: %v", err)
	}

	// Open the db connection
	db := db(dbHost, dbPort, dbUser, dbName, dbPassword, dbSslMode)

	// Create db schema
	err = Migrate(*db)
	if err != nil {
		log.Fatalf("Could not perform database migrations: %v", err)
	}

	defer db.Close()

	// Create the processor
	p := NewCertProcessor(k8sClient, certClient, acmeURL, certSecretPrefix, certNamespace, tagPrefix, namespaces, defaultProvider, defaultEmail, renewBeforeDays, db, workers)

	// Asynchronously start watching and refreshing certs
	wg := sync.WaitGroup{}
	doneChan := make(chan struct{})

	if len(p.namespaces) == 0 {
		wg.Add(1)
		go p.watchKubernetesEvents(
			v1.NamespaceAll,
			&wg,
			doneChan)
	} else {
		for _, namespace := range p.namespaces {
			wg.Add(1)
			go p.watchKubernetesEvents(
				namespace,
				&wg,
				doneChan,
			)
		}
	}
	wg.Add(1)
	go p.maintenance(time.Second*time.Duration(syncInterval), &wg, doneChan)

	wg.Add(1)
	go p.HTTPServer("5002", &wg, doneChan)

	log.Println("Kubernetes Certificate Controller started successfully.")

	// Listen for shutdown signals
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	log.Println("Shutdown signal received, exiting...")
	close(doneChan)
	wg.Wait()
	return
}
