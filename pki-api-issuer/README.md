# pki-api-issuer

#### nano /opt/apps/pki-master/pki-api-issuer/run.sh

```text
#!/usr/bin/env bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export JAVA_HOME="/opt/apps/java/21"

cd $DIR

$JAVA_HOME/bin/java -jar pki-api-issuer.jar --spring.config.location=file:./
```

#### sudo nano /etc/systemd/system/pki-api-issuer.service

```text
[Unit]
Description=pki-api-issuer
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=15
User=socheat
Group=socheat
WorkingDirectory=/opt/apps/pki-master/pki-api-issuer
ExecStart=/opt/apps/pki-master/pki-api-issuer/run.sh
StartLimitInterval=15

[Install]
WantedBy=multi-user.target
```

```shell
sudo chmod 755 /etc/systemd/system/pki-api-issuer.service
sudo systemctl enable pki-api-issuer
sudo systemctl daemon-reload
sudo systemctl start pki-api-issuer
sudo systemctl status pki-api-issuer
```