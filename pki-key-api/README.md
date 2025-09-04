# pki-key-api

#### nano /opt/apps/pki-master/pki-key-api/run.sh

```text
#!/usr/bin/env bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export JAVA_HOME="/opt/apps/java/21"

cd $DIR

$JAVA_HOME/bin/java -jar pki-key-api.jar --spring.config.location=file:./
```

#### sudo nano /etc/systemd/system/pki-key-api.service

```text
[Unit]
Description=pki-key-api
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=15
User=socheat
Group=socheat
WorkingDirectory=/opt/apps/pki-master/pki-key-api
ExecStart=/opt/apps/pki-master/pki-key-api/run.sh
StartLimitInterval=15

[Install]
WantedBy=multi-user.target
```

```shell
sudo chmod 755 /etc/systemd/system/pki-key-api.service
sudo systemctl enable pki-key-api
sudo systemctl daemon-reload
sudo systemctl start pki-key-api
sudo systemctl status pki-key-api
```