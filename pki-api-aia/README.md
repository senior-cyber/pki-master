# pki-api-aia

#### nano /opt/apps/pki-master/pki-api-aia/application-external.yaml

```yaml
override:
  server:
    port: 7011
  datasource:
    username: root
    password: password
    url: jdbc:mysql://localhost:3306/pki_master
  logging:
    file:
      path: /opt/apps/pki-master/pki-api-aia/
      name: pki-api-aia.log
```

#### sudo nano /etc/systemd/system/pki-api-aia.service

```text
[Unit]
Description=pki-api-aia
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
Group=root
WorkingDirectory=/opt/apps/pki-master/pki-api-aia
ExecStart=/opt/apps/java/17.0.8/bin/java -jar pki-api-aia.jar --spring.config.location=file:./,classpath:/ --spring.profiles.active=external
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
```

```shell
sudo chmod 755 /etc/systemd/system/pki-api-aia.service
sudo systemctl enable pki-api-aia
sudo systemctl daemon-reload
sudo systemctl start pki-api-aia
sudo systemctl status pki-api-aia
```

#### Default Credential

```text
http://${IP}:${WEB-PORT}
UID : admin
PWD : admin
```