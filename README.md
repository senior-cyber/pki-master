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

### Yubico Integration

```shell
sudo apt-get install cmake libtool libssl-dev pkg-config check libpcsclite-dev gengetopt help2man cmake libtool libssl-dev pkg-config check libpcsclite-dev gengetopt help2man zlib1g-dev
sudo apt install opensc-pkcs11 pcscd opensc

git clone https://github.com/Yubico/yubico-piv-tool.git
cd yubico-piv-tool
mkdir build; cd build
cmake ..
make
sudo make install
```

## Compile / Build

```shell
cd ~
git clone https://github.com/senior-cyber/pki-master.git
cd pki-master
./gradlew assemble bootJar

scp pki-api-crl/build/libs/pki-api-crl.jar       t460s:/opt/apps/pki-master/pki-api-crl
scp pki-api-ocsp/build/libs/pki-api-ocsp.jar     t460s:/opt/apps/pki-master/pki-api-ocsp
scp pki-api-x509/build/libs/pki-api-x509.jar     t460s:/opt/apps/pki-master/pki-api-x509
scp pki-root-api/build/libs/pki-root-api.jar     t460s:/opt/apps/pki-master/pki-root-api
scp pki-issuer-api/build/libs/pki-issuer-api.jar t460s:/opt/apps/pki-master/pki-issuer-api

sudo service pki-api-crl    restart
sudo service pki-api-ocsp   restart
sudo service pki-api-x509   restart
sudo service pki-root-api   restart
sudo service pki-issuer-api restart

```