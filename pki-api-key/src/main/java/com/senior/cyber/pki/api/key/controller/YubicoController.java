package com.senior.cyber.pki.api.key.controller;

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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class YubicoController {

    private static final Logger LOGGER = LoggerFactory.getLogger(YubicoController.class);

    @RequestMapping(path = "/yubico/info", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<Map<String, String>>> rootInfo(RequestEntity<Void> httpRequest) {
        YubiKitManager manager = new YubiKitManager();
        List<Map<String, String>> devices = new ArrayList<>();
        for (Map.Entry<YubiKeyDevice, DeviceInfo> p : manager.listAllDevices().entrySet()) {
            Map<String, String> _info = new HashMap<>();
            devices.add(_info);
            YubiKeyDevice device = p.getKey();
            DeviceInfo info = p.getValue();
            _info.put("transport", device.getTransport().name());
            _info.put("version", String.valueOf(info.getVersion()));
            if (info.getSerialNumber() != null) {
                _info.put("serialNumber", String.valueOf(info.getSerialNumber()));
            }
            if (info.getPartNumber() != null && !"null".equals(info.getPartNumber())) {
                _info.put("partNumber", info.getPartNumber());
            }
            _info.put("formFactor", info.getFormFactor().name());
            _info.put("versionName", info.getVersionName());
        }
        return ResponseEntity.ok(devices);
    }

}
