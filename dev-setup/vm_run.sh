export GOPATH=/home/vagrant/go
export KCM=$GOPATH/src/github.com/liquidweb/kube-cert-manager

echo "***************************** Spin up Postgres DB **********************************"
cd $KCM/dev-setup
sudo docker-compose up -d

echo "***************************** Spin up Boulder **************************************"
cd $GOPATH/src/github.com/letsencrypt/boulder
sudo docker-compose up -d