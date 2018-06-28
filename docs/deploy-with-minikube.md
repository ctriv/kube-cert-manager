# Deploy kube-cert-manager with minikube Guide

This guide will walk you through deploying the Kubernetes Certificate Manager on your local box using miniKube.
This guide also assumes that you have docker already installed, VM software like virtualBox, and GO. GO version 1.10 was
used in this guide.

## High Level Tasks
* Download and install minikube
* Build Persistent Volume and Persistent Volume Claim
* Build RBAC Permissions
* Build Kubernetes Custom Resource
* Clone and install kube-cert-manager dependencies
* Build the kube-cert-manager, create a docker image, and push to docker hub
* Deploy the kube-cert-manager image to minikube

## Installing minikube
For this example the installation of minikube was done for macOSX.

Installing instruction for minikube can be found https://kubernetes.io/docs/tasks/tools/install-minikube/
 
Install kubectl - https://kubernetes.io/docs/tasks/tools/install-kubectl/

`brew install kubectl`

Install minikube v0.28.0 - https://github.com/kubernetes/minikube/releases

`curl -Lo minikube https://storage.googleapis.com/minikube/releases/v0.28.0/minikube-darwin-amd64 && chmod +x minikube && sudo mv minikube /usr/local/bin/`

Start up minikube

`minikube start`

Start up the kubernetes dashboard (note if you don't see the dashboard come up give a moment and just refresh the page.)

`minikube dashboard`

At this point you should see the kubernetes dashboard and the minikube VM running on virtualBox or which VM software used.

Ssh into the minikube vm. 

`minikube ssh`

Create a directory for your persistent volume you will create.

`mkdir /var/lib/cert-manager`

## Build the persistent volume and persistent volume claims on the minikube
Create the persistent volume in kubernetes

`kubectl create -f persistent-volume.yaml` [persistent volume yaml file](/k8s/persistent-volume.yaml)

After this you should see the persistent volume in you kubernetes dashboard.

Create the persistent volume claim in kubernetes

`kubectl create -f volume.yaml` [persistent volume claim yaml file](/k8s/volume.yaml)

## Create service account user for kube-cert-manager
You need a service acccount so that the kube-cert-manager can talk with kubernetes and watch for
the cert objects.

Create the service account.

`kubectl create -f service-account.yaml` [service account yaml file](/k8s/service-account.yaml)

This service-account.yaml files does three things. 
1. It creates a new service account with name kube-cert-manager.
2. It creates a new cluster role with the same name and rules.
3. It creates a new cluster role binding for the service account and role.

If you do a `kubectl get serivceaccounts --namespace kube-system` you should see your service account there.
Same goes for the cluster role and the cluster role bindings.
`kubectl get clusterRoleBinding --namespace kube-system` and `kubectl get clusterRoles --namespace kube-system`

## Create the kubernetes custom resource Certificate
Create the customer resource

`kubectl create -f certificate-type.yaml` [certificate type yaml file](/k8s/certificate-type.yaml)

You can use its shortNames `cert and certs` in the `kubectl` command to get a single cert or a list of certs.

Creating certificates resources

`kubectl create -f cert-example.yaml` [cert example yaml file](/k8s/cert-example.yaml)

In the cert-example.yaml there is no namespace given. If you want to create the certificate object on a particular 
namespace add `namespace: "yourNamespace"` in he `metadata` section.

## Clone and install kube-cert-manager dependencies
Set up in your work environment a liquidweb.com folder then clone the kube-cert-manager into that folder.
Yout path should look like `/yourworkspace/liquidweb.com/kube-cert-manager`

Set up your GOPATH to the location of your project. If your GOPATH is in a different location you will have to copy the 
dependencies to that location before you build.

Download the Glide

`go get github.com/Masterminds/glide`

Download dependencies

`glide install`

After you do a glide install you should see all dependencies located in the vendor folder inside your project.
If you have any issues try deleting your glide cache located at `~/.glide/cache` and then try to install again.


## Build the kube-cert-manager and deploy to docker hub
Before we build the image and push to docker hub you must first set up an account with
[docker hub](https://hub.docker.com/). After setting up your account you will need to get with the
administrator and request access to the liquidweb repositories.

Then after you have access you can
`docker login` with your username and password

Create secret so that minikue can connect to docker hub. The registry-server is https://index.docker.io/v1

`kubectl create secret docker-registry regcred --docker-server=<your-registry-server> --docker-username=<your-name> --docker-password=<your-pword> --docker-email=<your-email>`

Build kube-cert-manager

`./build.sh`

Build docker image. Note that the `:test` is a branch or tag that you can add. So for example if you created a branch
called featurework and you want to build and push that image then you 
would change the build and push to `liquidweb/kube-cert-manager:featurework`

`docker build . -t liquidweb/kube-cert-manager:test`

Push docker image to docker hub

`docker push liquidweb/kube-cert-manager:test` 

If the push fails then you may need to re-login with `docker login`

## Deploy kube-cert-manager to your minikube setup
To deploy your image to your minikube environment update the deployment.yaml image. For example if we are will
working with kube-cert-manager:featurework then the name would be `liquidweb/kube-cert-manager:featurework`

`kubectl create -f deployment.yaml` [deployment yaml file](/k8s/deployment.yaml)

After deployment you should see a pod with the name kube-cert-manager.

##### Other helpful commands

```bash
 Check current context if you have sevral kube enviornments.
 kubectl config get-contexts
 
 Run kube-cert-manager outside of kubernetes
 ./kube-cert-manager -data-dir=data -default-email=creinhardt@liquidweb.com -kubeconfig=/Users/creinhardt/.kube/config -workers=8
  
```
