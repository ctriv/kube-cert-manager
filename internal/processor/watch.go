package processor

import (
	"log"
	"sync"

	"github.com/liquidweb/kube-cert-manager/internal/k8s"
	"k8s.io/client-go/pkg/api/v1"
)

func (p *CertProcessor) WatchKubernetesEvents(namespace string, wg *sync.WaitGroup, doneChan <-chan struct{}) {
	if namespace == v1.NamespaceAll {
		log.Printf("Watching certificates in all namespaces")
	} else {
		log.Printf("Watching certificates in namespace %s", namespace)
	}

	certEvents := p.k8s.MonitorCertificateEvents(namespace, doneChan)
	for {
		select {
		case event := <-certEvents:
			p.wp.Submit(func() {
				err := p.processCertificateEvent(event)
				if err != nil {
					log.Printf("Error while processing certificate event: %v", err)
				}
			})
		case <-doneChan:
			p.wp.Stop()
			wg.Done()
			log.Println("Stopped certificate event watcher.")
			return
		}
	}
}

func (p *CertProcessor) processCertificateEvent(c k8s.CertificateEvent) error {
	switch c.Type {
	case "ADDED", "MODIFIED":
		_, err := p.processCertificate(c.Object, false)
		return err
	}
	return nil
}
