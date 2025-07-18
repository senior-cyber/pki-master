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

# Public Key ==> OpenSSH Public Key
ssh-keygen -f mykey -i -m PKCS8 > mykey.pub
ssh-keygen -f mykey -e -m RFC4716 > mykey.pem

# Private Key ==> OpenSSH Public Key
ssh-keygen -y -f mykey > id_rsa.pub
```

## Convert PKCS#8 to OpenSSH Format vi-versa
```shell
# Generate RSA as RSA PRIVATE KEY
ssh-keygen -t rsa -b 1024 -m PEM -f mykey

# Generate RSA as OPENSSH PRIVATE KEY
ssh-keygen -t rsa -b 1024 -f pk

# Generate EC as EC PRIVATE KEY
ssh-keygen -t ecdsa -b 256 -m PEM -f mykey

# Generate EC as OPENSSH PRIVATE KEY
ssh-keygen -t ecdsa -b 256 -f mykey

# Convert Any Key ==> EC PRIVATE KEY or RSA PRIVATE KEY (According to its format)
ssh-keygen -p -f mykey -m PEM -m RFC4716 -N ""
ssh-keygen -p -f mykey -m PEM -m RFC4716 -N ""

# Convert Any Key ==> PRIVATE KEY 
ssh-keygen -p -f mykey -m PEM -m PKCS8 -N ""

# Convert Any Key ==> OPENSSH PRIVATE KEY
ssh-keygen -p -f mykey -N "" -C ""
```

### OpenSSH CA
```shell

1. 🔐 Generate Root CA Key
ssh-keygen -t rsa -b 1024 -f ssh_ca
# Creates:
# - ssh_ca        (private key)
# - ssh_ca.pub    (public key to copy to server)

2. 🔐 Generate User Key Pair
ssh-keygen -t rsa -b 1024 -f id_rsa_user
# Creates:
# - id_rsa_user        (user private key)
# - id_rsa_user.pub    (user public key)

3. 🖋️ Sign User Public Key with CA to Create SSH Certificate
ssh-keygen -s ssh_ca -I user-cert-id -n socheat -V +52w id_rsa_user.pub
# Flags:
# -s ssh_ca             : CA private key
# -I user-cert-id       : Certificate identity
# -n socheat            : Valid principal (username to match at login)
# -V +52w               : Valid for 52 weeks
This will generate id_rsa_user-cert.pub which is the signed certificate.


4. 🖥️ SSH Server Configuration (on the remote server)
4.1 Copy the CA public key to /etc/ssh/trusted-user-ca-keys.pem:
sudo cp ssh_ca.pub /etc/ssh/trusted-user-ca-keys.pem
# sudo wget http://192.168.1.53:3003/api/openssh/1981b9cb5e6.pub -O /etc/ssh/trusted-user-ca-keys.pem

4.2 Edit /etc/ssh/sshd_config:
# Add or uncomment the following line:
TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem

Then restart SSH:
sudo systemctl restart sshd

5. 🔐 Login Using Certificate

Ensure these files are in your ~/.ssh on the client:
~/.ssh/id_rsa_user             <- private key
~/.ssh/id_rsa_user-cert.pub    <- certificate

Ensure permissions are correct:
chmod 600 ~/.ssh/id_rsa_user
chmod 644 ~/.ssh/id_rsa_user-cert.pub

Then login:
ssh -i ~/.ssh/id_rsa_user socheat@your.server.ip
ssh -i ~/.ssh/id_rsa_user -o CertificateFile=/absolute/path/to/id_rsa_user-cert.pub socheat@host.example.com

/opt/homebrew/Cellar/openssh/9.9p2/bin/ssh-keygen -t ed25519-sk -C "`basename \`pwd\``-yubico" -f `pwd`/id_ed25519_sk
```

```text
Host myserver
  HostName your.server.ip
  User socheat
  IdentityFile ~/.ssh/id_rsa_user
  CertificateFile ~/.ssh/custom-cert.pub
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

sudo systemctl enable pki-api-crl    
sudo systemctl enable pki-api-ocsp   
sudo systemctl enable pki-api-x509   
sudo systemctl enable pki-root-api   
sudo systemctl enable pki-issuer-api

telegram endpoint, expose webhook for load test,
update access denied page, change session expired, please try again 
```

```shell
yubico-piv-tool -a verify-pin --sign -s 9c -A RSA2048 -H SHA256 -i data.txt -o data.sig
yubico-piv-tool -a set-touch -S 9c -T never -k 010203040506070801020304050607080102030405060708
ykman piv keys set-touch "9c" never
```

```text
Write API Integration, with OAuth2
```

```text
export KUBECONFIG=~/.kube/config-talos
kubectl get pod -n shopping
```