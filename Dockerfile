FROM golang:alpine as gobuilder

WORKDIR /go/src/github.com/liquidweb/kube-cert-manager
RUN apk update && apk add git bash curl && apk add --no-cache ca-certificates && update-ca-certificates
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | bash
COPY . .
RUN dep ensure
RUN CGO_ENABLED=0 go build

FROM scratch
COPY --from=gobuilder /go/src/github.com/liquidweb/kube-cert-manager/kube-cert-manager /app/kube-cert-manager
COPY --from=gobuilder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
WORKDIR /app
EXPOSE 5002/tcp
CMD ["/app/kube-cert-manager"]
