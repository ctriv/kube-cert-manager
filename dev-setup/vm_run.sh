echo "***************************** Spin up Postgres DB **********************************"
cd /go/src/github.com/liquidweb/kube-cert-manager/dev-setup
sudo docker-compose up -d

echo "***************************** Spin up Boulder **************************************"
cd /go/src/github.com/letsencrypt/boulder
sudo docker-compose up -d