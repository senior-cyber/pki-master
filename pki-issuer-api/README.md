# pki-issuer-api

#### nano /opt/apps/pki-master/pki-issuer-api/application-external.yaml

```yaml
override:
  server:
    port: 8021
  datasource:
    username: root
    password: password
    url: jdbc:mysql://localhost:3306/pki_master
  api:
    aia: http://api-aia.khmer.name:7011/api
    crl: http://api-crl.khmer.name:7012/api
  logging:
    file:
      path: /opt/apps/pki-master/pki-issuer-api/
      name: pki-issuer-api.log
```

#### sudo nano /etc/systemd/system/pki-issuer-api.service

```text
[Unit]
Description=pki-issuer-api
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
Group=root
WorkingDirectory=/opt/apps/pki-master/pki-issuer-api
ExecStart=/opt/apps/java/17.0.8/bin/java -jar pki-issuer-api.jar --spring.config.location=file:./,classpath:/ --spring.profiles.active=external
StartLimitInterval=0

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

#### Default Credential

```text
http://${IP}:${WEB-PORT}
UID : admin
PWD : admin
```