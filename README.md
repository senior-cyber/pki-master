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

# Client CLI

```text
./gradlew bootJar && java -Dapi=key -Dfunction=yubico-info -jar pki-client-cli/build/libs/pki-client-cli.jar
./gradlew bootJar && java -Dapi=key -Dfunction=bc-client-generate -Dsize=2048 -Dformat=RSA -jar pki-client-cli/build/libs/pki-client-cli.jar
./gradlew bootJar && java -Dapi=key -Dfunction=yubico-client-generate -Dsize=2048 -Dslot=9a -DserialNumber=23275988 -jar pki-client-cli/build/libs/pki-client-cli.jar
```

## Prerequisite

```shell
sudo apt-get install cmake libtool libssl-dev pkg-config check libpcsclite-dev gengetopt help2man cmake libtool libssl-dev pkg-config check libpcsclite-dev gengetopt help2man zlib1g-dev build-essential
sudo apt-get install opensc-pkcs11 pcscd opensc libusb-dev
# sudo apt-get install yubikey-manager
sudo apt update && sudo apt install ykcs11
```

```shell
git clone https://github.com/Yubico/yubico-piv-tool.git
cd yubico-piv-tool
mkdir build; cd build
cmake ..
make
sudo make install
sudo ldconfig
```

# Server Configuration

```shell
sudo addgroup scard
sudo usermod -aG scard "$USER"
```

## sudo nano /etc/polkit-1/rules.d/49-pcscd.rules

```text
// Allow members of "scard" (or "plugdev") to use pcscd
polkit.addRule(function(action, subject) {
    if ((action.id == "org.debian.pcsc-lite.access_pcsc" ||
         action.id == "org.debian.pcsc-lite.access_card") &&
        subject.isInGroup("scard")) {
        return polkit.Result.YES;
    }
});
```

```shell
sudo systemctl restart pcscd
```

## Compile / Build

```shell
cd ~
git clone https://github.com/senior-cyber/pki-master.git
cd pki-master
./gradlew clean bootJar

scp pki-api-crl/build/libs/pki-api-crl.jar       lenovo:/opt/apps/pki-master/pki-api-crl
scp pki-api-ocsp/build/libs/pki-api-ocsp.jar     lenovo:/opt/apps/pki-master/pki-api-ocsp
scp pki-api-x509/build/libs/pki-api-x509.jar     lenovo:/opt/apps/pki-master/pki-api-x509
scp pki-api-ssh/build/libs/pki-api-ssh.jar       lenovo:/opt/apps/pki-master/pki-api-ssh
scp pki-api-root/build/libs/pki-api-root.jar     lenovo:/opt/apps/pki-master/pki-api-root
scp pki-api-issuer/build/libs/pki-api-issuer.jar lenovo:/opt/apps/pki-master/pki-api-issuer
scp pki-api-key/build/libs/pki-api-key.jar       lenovo:/opt/apps/pki-master/pki-api-key
scp pki-api-revoke/build/libs/pki-api-revoke.jar lenovo:/opt/apps/pki-master/pki-api-revoke

cp pki-api-crl/build/libs/pki-api-crl.jar       /opt/apps/pki-master/pki-api-crl
cp pki-api-ocsp/build/libs/pki-api-ocsp.jar     /opt/apps/pki-master/pki-api-ocsp
cp pki-api-x509/build/libs/pki-api-x509.jar     /opt/apps/pki-master/pki-api-x509
cp pki-api-ssh/build/libs/pki-api-ssh.jar       /opt/apps/pki-master/pki-api-ssh
cp pki-api-root/build/libs/pki-api-root.jar     /opt/apps/pki-master/pki-api-root
cp pki-api-issuer/build/libs/pki-api-issuer.jar /opt/apps/pki-master/pki-api-issuer
cp pki-api-key/build/libs/pki-api-key.jar       /opt/apps/pki-master/pki-api-key
cp pki-api-revoke/build/libs/pki-api-revoke.jar /opt/apps/pki-master/pki-api-revoke

sudo service pki-api-crl    restart
sudo service pki-api-ocsp   restart
sudo service pki-api-x509   restart
sudo service pki-api-ssh    restart
sudo service pki-api-root   restart
sudo service pki-api-issuer restart
sudo service pki-api-key    restart
sudo service pki-api-revoke restart

sudo systemctl enable pki-api-crl
sudo systemctl enable pki-api-ocsp
sudo systemctl enable pki-api-x509
sudo systemctl enable pki-api-ssh
sudo systemctl enable pki-api-root
sudo systemctl enable pki-api-issuer
sudo systemctl enable pki-api-key
sudo systemctl enable pki-api-revoke
```

## Disable Touch

```shell
yubico-piv-tool -a verify-pin --sign -s 9c -A RSA2048 -H SHA256 -i data.txt -o data.sig
yubico-piv-tool -a set-touch -S 9c -T never -k 010203040506070801020304050607080102030405060708
ykman piv keys set-touch "9c" never
```

## Enable Feature

```text
# 1. Make sure CCID is on (not needed on default config)
ykman config usb --enable {OTP|U2F|FIDO2|OATH|PIV|OPENPGP|HSMAUTH}

# 2. Generate credentials on the YubiKey
yubihsm-auth setup --keyset-id 1 --label "Admin" --password-from-prompt

# 3. Connect to the HSM using those credentials
yubihsm-shell --authkey 1 --password-from-prompt
```

## Yubico OTP Integration

```text
ykman otp yubiotp 1 --serial-public-id --generate-private-id --generate-key

ykman otp yubiotp 1 --serial-public-id --generate-private-id --generate-key -O yubicloud.csv
https://upgrade.yubico.com/getapikey/

https://upload.yubico.com/
```

## Abbreviation

```text
Home / OTP / Short Touch (Slot 1) or Home / OTP / Long Touch (Slot 2)
- Yubico OTP - it is one time password authentication
- Challenge Response - it is offline challenge response verification, use for Linux PAM, Window Login, Mac Login
- Static Password - it is a static password auto fill
- OATH-HOTP - it is HMAC-based One-Time Password, 6 digit
Home / FIDO2 : it is Passkeys
Home / PIV (Personal Identity Verification) : it is x509 certificate

TOTP: it is Time-Base One-Time Password, 6 digit

PIN : it is PIN
PUK : it is PIN Unlock Code
```

# Platform SSO Reference

```shell
https://www.youtube.com/watch?v=INi-xKpYjbE&t=474s

Window Login
  - (https://support.microsoft.com/en-us/windows/configure-windows-hello-dae28983-8242-bb2a-d3d1-87c9d265a5f0)
  - https://github.com/privacyidea/pi-authenticator
  - https://github.com/privacyidea/privacyidea-credential-provider
MacOS Login 
  - (https://support.yubico.com/hc/en-us/articles/360016649059-YubiKey-for-macOS-login)
  - Platform SSO Extension + SSO Extension (https://twocanoes.com/products/mac/xcreds/)
Linux (https://developers.yubico.com/pam-u2f/)
  - Login (ubuntu/authd) - https://github.com/ubuntu/authd/tree/main
  - SSH
    - FIDO2
    - Yobico OTP
  - TTY
  - SUDO
Android
  - https://codelabs.developers.google.com/credential-manager-api-for-android?continue=https%3A%2F%2Fdeveloper.android.com%2Fcourses%2Fpathways%2Fpasskeys%23codelab-https%3A%2F%2Fcodelabs.developers.google.com%2Fcredential-manager-api-for-android#2
  - https://github.com/Yubico/yubikit-android
iOS
  - https://github.com/Yubico/yubikit-swift
  - https://developer.apple.com/documentation/authenticationservices/supporting-passkeys
```

# OpenSSH CA

```text
Reference
https://support.yubico.com/hc/en-us/articles/21010414002588-Using-the-YubiKey-PIV-application-for-SSH-authentication
```

## Create CA KEY

### Key in Yubico

```shell
curl --location 'https://pki-api-key.khmer.name/api/yubico/generate' \
--header 'Content-Type: application/json' \
--data '{
    "size": 2048,
    "format": "RSA",
    "serialNumber": "23275988",
    "slot": "9a",
    "managementKey": "010203040506070801020304050607080102030405060708"
}'
```

### Key

```shell
curl --location 'https://pki-api-key.khmer.name/api/jca/generate' \
--header 'Content-Type: application/json' \
--data '{
    "size": 2048,
    "format": "RSA"
}'
```

## Download CA KEY and load into SSH Server

```shell
sudo wget https://pki-api-key.khmer.name/api/openssh/60455daf-d120-4665-b258-aa1a5891509b.pub -O /etc/ssh/trusted-ca-keys.pub
```

## Globally Trusted

### sudo nano /etc/ssh/sshd_config.d/ssh-ca.conf

```text
TrustedUserCAKeys /etc/ssh/trusted-ca-keys.pub
```

### restart ssh server

```shell
sudo systemctl restart ssh
```

## Individual User Trusted

### nano ~/.ssh/authorized_keys

```text
cert-authority ${trusted-ca-keys.pub}
```

## Create SSH Client Key

### Key in Yubico

```shell
curl --location 'https://pki-api-key.khmer.name/api/yubico/generate' \
--header 'Content-Type: application/json' \
--data '{
    "size": 2048,
    "format": "RSA",
    "serialNumber": "23275988",
    "slot": "9a",
    "managementKey": "010203040506070801020304050607080102030405060708"
}'
```

### Key

```shell
curl --location 'https://pki-api-key.khmer.name/api/jca/generate' \
--header 'Content-Type: application/json' \
--data '{
    "size": 2048,
    "format": "RSA"
}'
```

## Sign SSH Client Key 

```shell
curl --location 'https://pki-issuer-api.khmer.name/api/ssh/generate' \
--header 'Content-Type: application/json' \
--data '{
  "issuer" : {
    "keyPassword" : "H2lDFsmr273kue4cAtU5",
    "keyId" : "60455daf-d120-4665-b258-aa1a5891509b"
  },
  "alias" : "test",
  "keyId" : "5db24db0-4726-4c66-874b-dc1fd0fc635f",
  "keyPassword" : "J2RsDKMpiRZKKgu3Gy94",
  "principal" : "socheat",
  "server" : "192.168.1.53",
  "validityPeriod" : 1
}'
```

## SSH Client Configuration

### PKCS#11 module for YubiKeys, libykcs11(yubico-piv-tool), it is support any slots

```text
libykcs11.so will be available after compile PKCS#11 module for YubiKeys
```

### nano ~/.ssh/config

```text
Host {alias}
    HostName {ip}
    User {user}
    PKCS11Provider /usr/local/lib/libykcs11.so
    IdentityFile id_rsa.pub
    CertificateFile id_rsa-cert.pub
```

### PKCS#11 module provided by OpenSC, it is support only 9a slot

```text
Host {alias}
    HostName {ip}
    User {user}
    PKCS11Provider /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
    CertificateFile id_rsa-cert.pub
```