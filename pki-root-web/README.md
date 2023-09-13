# pki-root-web

#### nano /opt/apps/pki-master/pki-root-web/application-external.yaml

```yaml
override:
  server:
    port: 8032
  webui:
    admin-lte: /opt/apps/github/ColorlibHQ/v3/AdminLTE
  datasource:
    username: root
    password: password
    url: jdbc:mysql://localhost:3306/pki_master
  api:
    aia: http://api-aia.khmer.name:7011/api
    crl: http://api-crl.khmer.name:7012/api
  logging:
    file:
      path: /opt/apps/pki-master/pki-root-web/
      name: pki-root-web.log
```

#### sudo nano /etc/systemd/system/pki-root-web.service

```text
[Unit]
Description=pki-root-web
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
Group=root
WorkingDirectory=/opt/apps/pki-master/pki-root-web
ExecStart=/opt/apps/java/17.0.8/bin/java -jar pki-root-web.jar --spring.config.location=file:./,classpath:/ --spring.profiles.active=external
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
```

```shell
sudo chmod 755 /etc/systemd/system/pki-root-web.service
sudo systemctl enable pki-root-web
sudo systemctl daemon-reload
sudo systemctl start pki-root-web
sudo systemctl status pki-root-web
```

#### Default Credential

```text
http://${IP}:${WEB-PORT}
UID : admin
PWD : admin
```