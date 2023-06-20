#!/bin/sh
echo "[+] Installing requirements..."
sudo apt install build-essential libcurl4-gnutls-dev libssh-dev fakeroot openssh-client -y
echo "[+] Creating required directories..."
mkdir bin
mkdir fs
mkdir logs
mkdir keys
echo "[+] Creating RSA keys for the server..."
ssh-keygen -t rsa -f keys/ssh_host_rsa
echo "[+] Compiling..."
make
echo "[+] Done compiling! To run the app use 'make run'"
