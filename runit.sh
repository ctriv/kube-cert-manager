#!/usr/bin/env bash

./kube-cert-manager \
-default-email=somedev@liquidweb.com \
-kubeconfig=~/.kube/config \
-acme-url=http://localhost:4000/directory \
-db-host=127.0.0.1 \
-db-port=5432 \
-db-username=postgres \
-db-name=certmanager \
-db-password=password \
-db-sslmode=require