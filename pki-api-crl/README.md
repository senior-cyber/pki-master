# pki-api-crl

#### nano /opt/apps/pki-master/pki-api-crl/run.sh

```text
#!/usr/bin/env bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export JAVA_HOME="/opt/apps/java/21"

cd $DIR

$JAVA_HOME/bin/java -jar pki-api-crl.jar --spring.config.location=file:./
```

#### sudo nano /etc/systemd/system/pki-api-crl.service

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

```shell
sudo chmod 755 /etc/systemd/system/pki-api-crl.service
sudo systemctl enable pki-api-crl
sudo systemctl daemon-reload
sudo systemctl start pki-api-crl
sudo systemctl status pki-api-crl
```