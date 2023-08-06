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

mkdir -p /opt/apps/pki-master
cp pki-web/build/libs/pki-web.jar /opt/apps/pki-master
cp pki-api/build/libs/pki-api.jar /opt/apps/pki-master
```

## PKI API

#### Configuration File (/opt/apps/pki-master/pki-api.yaml)

```yaml
OVERRIDE_SERVER_PORT: 4080
OVERRIDE_DB_URL: jdbc:mysql://localhost:3306/pki_master
OVERRIDE_DB_PORT: 3306
OVERRIDE_DB_UID: root
OVERRIDE_DB_PWD: password
OVERRIDE_DB_DRIVER: com.mysql.cj.jdbc.Driver
OVERRIDE_DB_DIALECT: org.hibernate.dialect.MySQL8Dialect 
OVERRIDE_LOG_FILE_PATH: /opt/apps/pki-master
OVERRIDE_LOG_FILE_NAME: pki-api.log
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
WorkingDirectory=/opt/apps/pki-master
ExecStart=${JDK-17}/bin/java -jar pki-api.jar --spring.config.location=classpath:/application.yaml,file:./pki-api.yaml
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

#### Configuration File (/opt/apps/pki-master/pki-web.yaml)

```yaml
OVERRIDE_SERVER_PORT: 5080
OVERRIDE_DB_URL: jdbc:mysql://localhost:3306/pki_master
OVERRIDE_DB_UID: root
OVERRIDE_DB_PWD: password
OVERRIDE_DB_DRIVER: com.mysql.cj.jdbc.Driver
OVERRIDE_DB_DIALECT: org.hibernate.dialect.MySQL8Dialect
OVERRIDE_ADMIN_LTE: /opt/apps/ColorlibHQ/AdminLTE
OVERRIDE_PKI_API_URL: http://localhost:4080
OVERRIDE_LOG_FILE_PATH: /opt/apps/pki-master
OVERRIDE_LOG_FILE_NAME: pki-web.log
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
WorkingDirectory=/opt/apps/pki-master
ExecStart=${JDK-17}/bin/java -jar pki-web.jar --spring.config.location=classpath:/application.yaml,file:./pki-web.yaml
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