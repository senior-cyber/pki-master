# pki-api-crl

#### nano /opt/apps/pki-master/pki-issuer-api/run.sh

```text
#!/usr/bin/env bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export JAVA_HOME="/opt/apps/java/21"

cd $DIR

$JAVA_HOME/bin/java -jar pki-issuer-api.jar --spring.config.location=file:./
```

#### sudo nano /etc/systemd/system/pki-issuer-api.service

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
StartLimitInterval=15

[Install]
WantedBy=multi-user.target
```

```shell
sudo chmod 755 /etc/systemd/system/pki-issuer-api.service
sudo systemctl enable pki-issuer-api
sudo systemctl daemon-reload
sudo systemctl start pki-issuer-api
sudo systemctl status pki-issuer-api
```