# Support
#### Apache2
#### Tomcat (Apr+Nio)
#### Gitlab
#### SpringBoot

# Prerequisite

```text
JDK 17 - https://www.azul.com/downloads/?version=java-17-lts&os=ubuntu&architecture=x86-64-bit&package=jdk
MySQL 8 - sudo apt-get install mysql-server
```

# Compile / Build

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

# PKI API
#### Configuration File (/opt/apps/pki-master/pki-api.yaml)
```yaml
server:
  port: 4080
spring:
  jpa:
    properties:
      hibernate:
        dialect: org.hibernate.dialect.MySQL8Dialect
        format_sql: true
    show-sql: true
    hibernate:
      ddl-auto: none
      naming:
        physical-strategy: org.hibernate.boot.model.naming.PhysicalNamingStrategyStandardImpl
  mvc:
    servlet:
      path: /api
      load-on-startup: 1
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    username: root
    password: password
    url: jdbc:mysql://localhost:3306/my_pki
  flyway:
    locations: classpath:com/senior/cyber/pki/dao/flyway
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
ExecStart=/opt/apps/java/17.0.7/bin/java -jar /opt/apps/pki-master/pki-api.jar --spring.config.location=file:///opt/apps/pki-master/ --spring.config.name=pki-api
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

# PKI WEB
#### Configuration File (/opt/apps/pki-master/pki-web.yaml)
```yaml
server:
  port: 5080
webui:
  servlet:
    load-on-startup: 1
    path: /*
  configuration-type: DEPLOYMENT
  wicket-factory: com.senior.cyber.pki.web.factory.WicketFactory
  pkg: com.senior.cyber.pki.web.pages
  admin-lte: /opt/apps/ColorlibHQ/AdminLTE
  csrf: false
pki:
  api:
    address:
      - http://192.168.1.140:4080
spring:
  jpa:
    properties:
      hibernate:
        dialect: org.hibernate.dialect.MySQL8Dialect
        format_sql: true
    hibernate:
      ddl-auto: none
      naming:
        physical-strategy: org.hibernate.boot.model.naming.PhysicalNamingStrategyStandardImpl
    show-sql: true
  mvc:
    servlet:
      path: /api
      load-on-startup: 1
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    username: root
    password: password
    url: jdbc:mysql://localhost:3306/my_pki
  flyway:
    locations: classpath:com/senior/cyber/pki/dao/flyway
app:
  mode: Individual
  secret: 12345678
crypto:
  iv: Lxomdim3thxLYtOu8NmaXg==
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
ExecStart=/opt/apps/java/17.0.7/bin/java -jar /opt/apps/pki-master/pki-web.jar --spring.config.location=file:///opt/apps/pki-master/ --spring.config.name=pki-web
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
```

```shell
sudo chmod 755 /etc/systemd/system/pki-web.service
sudo systemctl enable pki-web
sudo systemctl daemon-reload
sudo service pki-web start
sudo service pki-web status
```

#### Default Credential
```text
http://192.168.1.140:5080
UID : admin
PWD : admin
```