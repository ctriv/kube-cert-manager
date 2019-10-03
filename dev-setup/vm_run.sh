export GOPATH=/home/vagrant/go

echo "***************************** Spin up Postgres DB **********************************"
cd $GOPATH/src/github.com/liquidweb/kube-cert-manager/dev-setup
sudo docker-compose up -d

echo "***************************** Spin up Boulder **************************************"
cd $GOPATH/src/github.com/letsencrypt/boulder
sudo docker-compose up -d