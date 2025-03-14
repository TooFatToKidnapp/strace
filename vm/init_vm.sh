#!/bin/bash

set -ex

source /vagrant/.ssh_env

apt update
apt upgrade -y
apt install make clang gcc vim curl git strace -y

sudo -u vagrant bash -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
sudo -u vagrant bash -c 'echo "export PATH=\$HOME/.cargo/bin:\$PATH" >> ~/.bashrc'
sudo -u vagrant bash -c 'source ~/.bashrc'


echo $SSH_KEY >> /home/vagrant/.ssh/authorized_keys
