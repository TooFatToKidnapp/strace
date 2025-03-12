#!/bin/bash

set -ex

source /vagrant/.ssh_env

apt update
apt upgrade -y
apt install make clang gcc vim curl git strace -y


echo $SSH_KEY >> /home/vagrant/.ssh/authorized_keys
