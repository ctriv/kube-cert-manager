#!/usr/bin/env bash

echo "***************************** Update System Packages ***************************"
sudo -E apt-get update
sudo -E apt-get -y upgrade

echo "***************************** Install psql *************************************"
sudo apt install -y postgresql-client-common
sudo apt-get install -y postgresql-client

echo "***************************** Install Docker **********************************"
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"
sudo apt update
sudo apt install -y docker-ce
sudo apt install -y docker-compose

echo "***************************** Spin up Postgres DB **********************************"
sudo docker-compose up -d