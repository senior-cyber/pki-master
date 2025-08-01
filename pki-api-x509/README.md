# pki-api-x509

#### nano /opt/apps/pki-master/pki-api-x509/run.sh

```text
#!/usr/bin/env bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export JAVA_HOME="/opt/apps/java/21"

cd $DIR

$JAVA_HOME/bin/java -jar pki-api-x509.jar --spring.config.location=file:./
```

#### sudo nano /etc/systemd/system/pki-api-x509.service

```text
[Unit]
Description=pki-api-x509
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=15
User=socheat
Group=socheat
WorkingDirectory=/opt/apps/pki-master/pki-api-x509
ExecStart=/opt/apps/pki-master/pki-api-x509/run.sh
StartLimitInterval=15

[Install]
WantedBy=multi-user.target
```

```shell
sudo chmod 755 /etc/systemd/system/pki-api-x509.service
sudo systemctl enable pki-api-x509
sudo systemctl daemon-reload
sudo systemctl start pki-api-x509
sudo systemctl status pki-api-x509
```