package com.senior.cyber.pki.api.key.controller;

import com.senior.cyber.pki.common.dto.YubicoInfo;
import com.senior.cyber.pki.common.dto.YubicoInfoResponse;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.desktop.YubiKitManager;
import com.yubico.yubikit.management.DeviceInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class YubicoController {

    private static final Logger LOGGER = LoggerFactory.getLogger(YubicoController.class);

    @RequestMapping(path = "/yubico/info", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<YubicoInfoResponse> yubicoInfo(RequestEntity<Void> httpRequest) {
        YubiKitManager manager = new YubiKitManager();
        YubicoInfoResponse response = new YubicoInfoResponse();
        for (Map.Entry<YubiKeyDevice, DeviceInfo> p : manager.listAllDevices().entrySet()) {
            YubicoInfo _info = new YubicoInfo();
            response.getItems().add(_info);
            YubiKeyDevice device = p.getKey();
            DeviceInfo info = p.getValue();
            _info.setTransport(device.getTransport().name());
            _info.setVersion(String.valueOf(info.getVersion()));
            if (info.getSerialNumber() != null) {
                _info.setSerialNumber(String.valueOf(info.getSerialNumber()));
            }
            if (info.getPartNumber() != null && !"null".equals(info.getPartNumber())) {
                _info.setPartNumber(String.valueOf(info.getPartNumber()));
            }
            _info.setFormFactor(info.getFormFactor().name());
            _info.setVersionName(info.getVersionName());
        }
        return ResponseEntity.ok(response);
    }

}
