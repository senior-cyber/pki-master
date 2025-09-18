# pki-api-queue

#### nano /opt/apps/pki-master/pki-api-queue/run.sh

```text
#!/usr/bin/env bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export JAVA_HOME="/opt/apps/java/21"

cd $DIR

$JAVA_HOME/bin/java -jar pki-api-queue.jar --spring.config.location=file:./
```

#### sudo nano /etc/systemd/system/pki-api-queue.service

```text
[Unit]
Description=pki-api-queue
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=15
User=socheat
Group=socheat
WorkingDirectory=/opt/apps/pki-master/pki-api-queue
ExecStart=/opt/apps/pki-master/pki-api-queue/run.sh
StartLimitInterval=15

[Install]
WantedBy=multi-user.target
```

```shell
sudo chmod 755 /etc/systemd/system/pki-api-queue.service
sudo systemctl enable pki-api-queue
sudo systemctl daemon-reload
sudo systemctl start pki-api-queue
sudo systemctl status pki-api-queue
```