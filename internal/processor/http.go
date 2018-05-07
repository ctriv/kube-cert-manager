package processor

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

func (p *CertProcessor) HTTPServer(port string, wg *sync.WaitGroup, doneChan <-chan struct{}) {
	r := mux.NewRouter()

	for _, ca := range p.CAs {
		ca.SetupRoute(r)
	}

	srv := &http.Server{
		Addr:         ":" + port,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r,
	}

	go func() {
		log.Println("Starting HTTP challange server.")
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	<-doneChan
	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), 5)
	defer cancel()
	defer wg.Done()
	log.Println("Stopping HTTP challange server.")
	srv.Shutdown(ctx)

}
