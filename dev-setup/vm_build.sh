#!/usr/bin/env bash

echo "***************************** Update System Packages *******************************"
sudo -E apt-get update
sudo -E apt-get -y upgrade

echo "***************************** Setup Go *********************************************"
sudo add-apt-repository -y ppa:longsleep/golang-backports
sudo apt-get update
sudo apt-get install -y golang-go
sudo apt-get install -y go-dep
export GOPATH=/home/vagrant/go
echo "export GOPATH=/home/vagrant/go" >> /home/vagrant/.bashrc
sudo mkdir $GOPATH/bin
sudo mkdir $GOPATH/pkg

echo "***************************** Install psql *****************************************"
sudo apt install -y postgresql-client-common
sudo apt-get install -y postgresql-client

echo "***************************** Install Docker ***************************************"
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"
sudo apt update
sudo apt install -y docker-ce
sudo apt install -y docker-compose

echo "***************************** Spin up Postgres DB **********************************"
cd $GOPATH/src/github.com/liquidweb/kube-cert-manager/dev-setup
sudo docker-compose up -d

echo "***************************** Install Boulder **************************************"
sudo mkdir $GOPATH/src/github.com/letsencrypt
cd $GOPATH/src/github.com/letsencrypt
sudo git clone https://github.com/letsencrypt/boulder.git
cd boulder
sudo docker-compose up -d