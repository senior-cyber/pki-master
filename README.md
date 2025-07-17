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

## Convert PKCS#1 to PKCS#8

```shell
openssl pkcs8 -topk8 -inform PEM -outform PEM -in input.pem -out output.pem -nocrypt
```

## Convert PKCS#8 to OpenSSH Format

```shell
ssh-keygen -f public_key.pem -i -m PKCS8 > id_rsa.pub
ssh-keygen -y -f private_key.pem > id_rsa.pub

ssh-keygen -i -f private_key.pem -m PKCS8 > openssh_private.key
```

## Convert PKCS#8 to OpenSSH Format vi-versa
```shell
# Generate RSA as RSA PRIVATE KEY
ssh-keygen -t rsa -b 1024 -m PEM -f mykey

# Generate RSA as OPENSSH PRIVATE KEY
ssh-keygen -t rsa -b 1024 -f mykey

# Generate EC as EC PRIVATE KEY
ssh-keygen -t ecdsa -b 256 -m PEM -f mykey

# Generate EC as OPENSSH PRIVATE KEY
ssh-keygen -t ecdsa -b 256 -f mykey

# Convert Any Key ==> EC PRIVATE KEY or RSA PRIVATE KEY (According to its format)
ssh-keygen -p -f mykey -m PEM -m RFC4716 -N ""

# Convert Any Key ==> PRIVATE KEY 
ssh-keygen -p -f mykey -m PEM -m PKCS8 -N ""

# Convert Any Key ==> OPENSSH PRIVATE KEY
ssh-keygen -p -f mykey -N ""
```

## Prerequisite

### Yubico Integration

```shell
sudo apt-get install cmake libtool libssl-dev pkg-config check libpcsclite-dev gengetopt help2man cmake libtool libssl-dev pkg-config check libpcsclite-dev gengetopt help2man zlib1g-dev build-essential
sudo apt-get install opensc-pkcs11 pcscd opensc libusb-dev

git clone https://github.com/Yubico/yubico-piv-tool.git
cd yubico-piv-tool
mkdir build; cd build
cmake ..
make
sudo make install
sudo ldconfig

sudo addgroup scard
sudo usermod -aG scard "$USER"
```

### sudo nano /etc/polkit-1/rules.d/49-pcscd.rules

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

```shell
yubico-piv-tool -a verify-pin --sign -s 9c -A RSA2048 -H SHA256 -i data.txt -o data.sig
yubico-piv-tool -a set-touch -S 9c -T never -k 010203040506070801020304050607080102030405060708
ykman piv keys set-touch "9c" never
```