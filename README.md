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

## Compile / Build

```shell
cd ~
git clone https://github.com/senior-cyber/pki-master.git
cd pki-master
./gradlew assemble bootJar

sudo service pki-root-api stop
sudo service pki-issuer-api stop
sudo service pki-api-aia stop
sudo service pki-api-crl stop

mkdir -p /opt/apps/pki-master/pki-root-api
mkdir -p /opt/apps/pki-master/pki-issuer-api
mkdir -p /opt/apps/pki-master/pki-api-aia
mkdir -p /opt/apps/pki-master/pki-api-crl

scp pki-api-aia/build/libs/pki-api-aia.jar       t460s:/opt/apps/pki-master/pki-api-aia
scp pki-api-crl/build/libs/pki-api-crl.jar       t460s:/opt/apps/pki-master/pki-api-crl
scp pki-root-api/build/libs/pki-root-api.jar     t460s:/opt/apps/pki-master/pki-root-api
scp pki-issuer-api/build/libs/pki-issuer-api.jar t460s:/opt/apps/pki-master/pki-issuer-api

sudo systemctl enable pki-api-aia.service
sudo systemctl enable pki-api-crl.service
sudo systemctl enable pki-root-api.service
sudo systemctl enable pki-issuer-api.service

sudo service pki-api-aia restart
sudo service pki-api-crl restart
sudo service pki-root-api restart
sudo service pki-issuer-api restart

sudo service pki-api-aia stop
sudo service pki-api-crl stop
sudo service pki-root-api stop
sudo service pki-issuer-api stop
```

# sudo nano /etc/systemd/system/pki-api-aia.service

```text
[Unit]
Description=pki-api-aia
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=15
User=socheat
Group=socheat
WorkingDirectory=/opt/apps/pki-master/pki-api-aia
ExecStart=/opt/apps/pki-master/pki-api-aia/run.sh
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
```

# sudo nano /etc/systemd/system/pki-api-crl.service

```text
[Unit]
Description=pki-api-crl
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=15
User=socheat
Group=socheat
WorkingDirectory=/opt/apps/pki-master/pki-api-crl
ExecStart=/opt/apps/pki-master/pki-api-crl/run.sh
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
```

# sudo nano /etc/systemd/system/pki-root-api.service

```text
[Unit]
Description=pki-root-api
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=15
User=socheat
Group=socheat
WorkingDirectory=/opt/apps/pki-master/pki-root-api
ExecStart=/opt/apps/pki-master/pki-root-api/run.sh
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
```

# sudo nano /etc/systemd/system/pki-issuer-api.service

```text
[Unit]
Description=pki-issuer-api
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=15
User=socheat
Group=socheat
WorkingDirectory=/opt/apps/pki-master/pki-issuer-api
ExecStart=/opt/apps/pki-master/pki-issuer-api/run.sh
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
```