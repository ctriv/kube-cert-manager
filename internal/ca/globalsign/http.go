package globalsign

import (
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

func (ca *certAuthority) SetupRoute(router *mux.Router) {
	router.HandleFunc("/.well-known/pki-validation/gsdv.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain")
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
		keyAuth, ok := ca.challanges.Load(host)

		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
			return
		}

		w.Write([]byte(keyAuth.(string)))
	})
}

func (ca *certAuthority) addHTTPChallange(host, secret string) {
	ca.challanges.Store(host, secret)
}

func (ca *certAuthority) removeHTTPChallange(host string) {
	ca.challanges.Delete(host)
}
