package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

type httpRouterProvider struct {
	challenges *sync.Map
}

func newHttpRouterProvider() *httpRouterProvider {
	return &httpRouterProvider{
		challenges: new(sync.Map),
	}
}

func (h *httpRouterProvider) Present(domain, token, keyAuth string) error {
	h.challenges.Store(keyFor(domain, token), keyAuth)

	return nil
}

func (h *httpRouterProvider) CleanUp(domain, token, keyAuth string) error {
	h.challenges.Delete(keyFor(domain, token))

	return nil
}

func keyFor(domain, token string) string {
	return domain + "|" + token
}

func (p *CertProcessor) HTTPServer(port string, wg *sync.WaitGroup, doneChan <-chan struct{}) {
	r := mux.NewRouter()

	r.HandleFunc("/.well-known/acme-challenge/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain")

		vars := mux.Vars(r)
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			log.Printf("Couldn't split %s into host and port: %v", r.Host, err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error"))
			return
		}

		keyAuth, ok := p.httpProvider.challenges.Load(keyFor(host, vars["id"]))

		if !ok {
			log.Printf("No answer for %s/.well-known/acme-challange/%s", r.Host, vars["id"])
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
			return
		}

		w.Write([]byte(keyAuth.(string)))
	})

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
