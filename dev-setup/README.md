# kube-cert-manager development setup
Vagrantfile build of the kube cert manager

This process will install the kube cert manager, a boulder local instance, and a
postgres instance.

## Pre-Installation
1. Make sure you have `vagrant` and `virtual box` installed

## Installation Instructions
1. git clone this repo
2. Enter into `kube-cert-manager` directory
3. `$ vagrant up`

## Usage
1. `$ vagrant ssh` to log into your vm

## Cleanup
1. `$ vagrant halt` to shutdown your vm
2. `$ vagrant destroy` to destroy your vm