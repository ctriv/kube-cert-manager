FROM golang:alpine as gobuilder

WORKDIR /go/src/github.com/liquidweb/kube-cert-manager
COPY . .
RUN CGO_ENABLED=0 go build

FROM scratch
COPY --from=gobuilder /go/src/github.com/liquidweb/kube-cert-manager/kube-cert-manager /app/kube-cert-manager
WORKDIR /app
EXPOSE 5002/tcp
CMD ["/app/kube-cert-manager"]
