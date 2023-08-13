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
mkdir -p /opt/apps/ColorlibHQ
cd /opt/apps/ColorlibHQ
git clone https://github.com/ColorlibHQ/AdminLTE.git

cd ~
git clone https://github.com/senior-cyber/frmk-master.git
cd frmk-master
make build

cd ~
git clone https://github.com/senior-cyber/pki-master.git
cd pki-master
make build

mkdir -p /opt/apps/pki-master/web
cp pki-web/build/libs/pki-web.jar /opt/apps/pki-master/web

mkdir -p /opt/apps/pki-master/api
cp pki-api/build/libs/pki-api.jar /opt/apps/pki-master/api
```

## PKI API

#### Configuration File (/opt/apps/pki-master/api/application-external.yaml)

```yaml
override:
  server:
    port: 4080
  datasource:
    username: root
    password: password
    url: jdbc:mysql://localhost:3306/pki_master
  logging:
    file:
      path: /opt/apps/pki-master/api/
      name: pki-api.log
```

#### SystemD Configuration

```text
[Unit]
Description=pki-api
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
Group=root
WorkingDirectory=/opt/apps/pki-master/api
ExecStart=${JDK-17}/bin/java -jar pki-api.jar  --spring.config.location=file:./,classpath:/ --spring.profiles.active=external
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
```

```shell
sudo chmod 755 /etc/systemd/system/pki-api.service
sudo systemctl enable pki-api
sudo systemctl daemon-reload
sudo service pki-api start
sudo service pki-api status
```

## PKI WEB

#### Configuration File (/opt/apps/pki-master/web/application-external.yaml)

```yaml
override:
  server:
    port: 5080
  webui:
    admin-lte: /Users/socheatkhauv/github/ColorlibHQ/v3
  pki:
    api:
      address-1: http://localhost:4080
  datasource:
    username: root
    password: password
    url: jdbc:mysql://localhost:3306/pki_master
  logging:
    file:
      path: /opt/apps/pki-master/web/
      name: pki-web.log
```

#### SystemD Configuration

```text
[Unit]
Description=pki-web
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
Group=root
WorkingDirectory=/opt/apps/pki-master/web
ExecStart=${JDK-17}/bin/java -jar pki-web.jar --spring.config.location=file:./,classpath:/ --spring.profiles.active=external
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
```

```shell
sudo chmod 755 /etc/systemd/system/pki-web.service
sudo systemctl enable pki-web
sudo systemctl daemon-reload
sudo systemctl start pki-web 
sudo systemctl status pki-web
```

#### Default Credential

```text
http://${IP}:${WEB-PORT}
UID : admin
PWD : admin
```