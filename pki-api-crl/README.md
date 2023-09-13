# pki-api-crl

#### nano /opt/apps/pki-master/pki-api-crl/application-external.yaml

```yaml
override:
  server:
    port: 7012
  datasource:
    username: root
    password: password
    url: jdbc:mysql://localhost:3306/pki_master
  logging:
    file:
      path: /opt/apps/pki-master/pki-api-crl/
      name: pki-api-crl.log
```

#### sudo nano /etc/systemd/system/pki-api-crl.service

```text
[Unit]
Description=pki-api-crl
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
Group=root
WorkingDirectory=/opt/apps/pki-master/pki-api-crl
ExecStart=/opt/apps/java/17.0.8/bin/java -jar pki-api-crl.jar --spring.config.location=file:./,classpath:/ --spring.profiles.active=external
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

#### Default Credential

```text
http://${IP}:${WEB-PORT}
UID : admin
PWD : admin
```