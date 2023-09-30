## Tested

| No | Name             |
|----|------------------|
| 1  | Apache2          |
| 2  | Tomcat (Apr+Nio) |
| 3  | Gitlab           |
| 4  | SpringBoot       |
| 5  | Golang           |
| 6  | Java             |
| 7  | PHP              |
| 8  | .Net             |
| 9  | C/C++            |
| 10 | Android          |
| 11 | Kotlin           |
| 12 | iOS              |
| 13 | Swift            |
| 14 | Objective-C      |

## Prerequisite

```text
JDK 17 - https://www.azul.com/downloads/?version=java-17-lts&os=ubuntu&architecture=x86-64-bit&package=jdk
MySQL 8 - sudo apt-get install mysql-server
```

## Compile / Build

```shell
mkdir -p /opt/apps/github/ColorlibHQ/v3
cd /opt/apps/github/ColorlibHQ/v3
git clone https://github.com/ColorlibHQ/AdminLTE.git

cd ~
git clone https://github.com/senior-cyber/frmk-master.git
cd frmk-master
make build

cd ~
git clone https://github.com/senior-cyber/pki-master.git
cd pki-master
make build

sudo service pki-root-web stop
sudo service pki-root-api stop
sudo service pki-issuer-web stop
sudo service pki-issuer-api stop
sudo service pki-api-aia stop
sudo service pki-api-crl stop

mkdir -p /opt/apps/pki-master/pki-root-web
cp pki-root-web/build/libs/pki-root-web.jar /opt/apps/pki-master/pki-root-web

mkdir -p /opt/apps/pki-master/pki-root-api
cp pki-root-api/build/libs/pki-root-api.jar /opt/apps/pki-master/pki-root-api

mkdir -p /opt/apps/pki-master/pki-issuer-web
cp pki-issuer-web/build/libs/pki-issuer-web.jar /opt/apps/pki-master/pki-issuer-web

mkdir -p /opt/apps/pki-master/pki-issuer-api
cp pki-issuer-api/build/libs/pki-issuer-api.jar /opt/apps/pki-master/pki-issuer-api

mkdir -p /opt/apps/pki-master/pki-api-aia
cp pki-api-aia/build/libs/pki-api-aia.jar /opt/apps/pki-master/pki-api-aia

mkdir -p /opt/apps/pki-master/pki-api-crl
cp pki-api-crl/build/libs/pki-api-crl.jar /opt/apps/pki-master/pki-api-crl
```