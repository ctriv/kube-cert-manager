package acme

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/mux"
)

type httpRouterProvider struct {
	challanges *sync.Map
}

func newHttpRouteProvider() *httpRouterProvider {
	return &httpRouterProvider{
		challanges: new(sync.Map),
	}
}

func (h *httpRouterProvider) SetupRoute(router *mux.Router) {
	router.HandleFunc("/.well-known/acme-challenge/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain")

		vars := mux.Vars(r)
		host := r.Host
		if strings.Contains(host, ":") {
			var err error
			host, _, err = net.SplitHostPort(r.Host)
			if err != nil {
				log.Printf("Couldn't split %s into host and port: %v", r.Host, err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error"))
				return
			}
		}
		keyAuth, ok := h.challanges.Load(keyFor(host, vars["id"]))

		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
			return
		}

		w.Write([]byte(keyAuth.(string)))
	})
}

func (h *httpRouterProvider) Present(domain, token, keyAuth string) error {
	h.challanges.Store(keyFor(domain, token), keyAuth)

	return nil
}

func (h *httpRouterProvider) CleanUp(domain, token, keyAuth string) error {
	h.challanges.Delete(keyFor(domain, token))

	return nil
}

func keyFor(domain, token string) string {
	return domain + "|" + token
}
