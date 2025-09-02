# pki-api-ssh

#### nano /opt/apps/pki-master/pki-api-ssh/run.sh

```text
#!/usr/bin/env bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export JAVA_HOME="/opt/apps/java/21"

cd $DIR

$JAVA_HOME/bin/java -jar pki-api-ssh.jar --spring.config.location=file:./
```

#### sudo nano /etc/systemd/system/pki-api-ssh.service

```text
[Unit]
Description=pki-api-ssh
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=15
User=socheat
Group=socheat
WorkingDirectory=/opt/apps/pki-master/pki-api-ssh
ExecStart=/opt/apps/pki-master/pki-api-ssh/run.sh
StartLimitInterval=15

[Install]
WantedBy=multi-user.target
```

```shell
sudo chmod 755 /etc/systemd/system/pki-api-ssh.service
sudo systemctl enable pki-api-ssh
sudo systemctl daemon-reload
sudo systemctl start pki-api-ssh
sudo systemctl status pki-api-ssh
```