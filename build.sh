#!/usr/bin/env bash

git pull

./gradlew clean bootJar

sudo systemctl stop pki-api-crl
sudo systemctl stop pki-api-ocsp
sudo systemctl stop pki-api-ssh
sudo systemctl stop pki-api-x509
sudo systemctl stop pki-api-revoke
sudo systemctl stop pki-api-issuer
sudo systemctl stop pki-api-key
sudo systemctl stop pki-api-root

cp pki-api-crl/build/libs/pki-api-crl.jar       /opt/apps/pki-master/pki-api-crl
cp pki-api-revoke/build/libs/pki-api-revoke.jar /opt/apps/pki-master/pki-api-revoke
cp pki-api-ocsp/build/libs/pki-api-ocsp.jar     /opt/apps/pki-master/pki-api-ocsp
cp pki-api-x509/build/libs/pki-api-x509.jar     /opt/apps/pki-master/pki-api-x509
cp pki-api-ssh/build/libs/pki-api-ssh.jar       /opt/apps/pki-master/pki-api-ssh
cp pki-api-root/build/libs/pki-api-root.jar     /opt/apps/pki-master/pki-api-root
cp pki-api-issuer/build/libs/pki-api-issuer.jar /opt/apps/pki-master/pki-api-issuer
cp pki-api-key/build/libs/pki-api-key.jar       /opt/apps/pki-master/pki-api-key

sudo systemctl start pki-api-crl
sudo systemctl start pki-api-revoke
sudo systemctl start pki-api-ocsp
sudo systemctl start pki-api-ssh
sudo systemctl start pki-api-x509
sudo systemctl start pki-api-issuer
sudo systemctl start pki-api-key
sudo systemctl start pki-api-root
