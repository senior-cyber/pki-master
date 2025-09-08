package com.senior.cyber.pki.key.api.controller;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.x509.KeyFormat;
import com.senior.cyber.pki.common.x509.PrivateKeyUtils;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.KeyService;
import com.senior.cyber.pki.service.UserService;
import com.senior.cyber.pki.service.util.YubicoProviderUtils;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.Slot;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

@RestController
public class KeyController {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyController.class);

    @Autowired
    protected KeyService keyService;

    @Autowired
    protected UserService userService;

    @Autowired
    protected KeyRepository keyRepository;

    @Value("${api.ssh}")
    protected String sshApi;

    @RequestMapping(path = "/info", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<KeyInfoResponse> info(RequestEntity<Void> httpRequest, @RequestParam("id") String id) {
        Key key = this.keyRepository.findById(id).orElseThrow();

        KeyInfoResponse response = new KeyInfoResponse();
        response.setId(key.getId());
        if (key.getType() != null) {
            response.setType(key.getType().name());
        }
        if (key.getKeyFormat() != null) {
            response.setKeyFormat(key.getKeyFormat().name());
        }
        response.setPrivateKey(PrivateKeyUtils.convert(key.getPrivateKey()));
        response.setPublicKey(key.getPublicKey());
        response.setCreatedDatetime(key.getCreatedDatetime());
        if (key.getKeySize() > 0) {
            response.setKeySize(key.getKeySize());
        }
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/jca/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JcaKeyGenerateResponse> jcaGenerate(RequestEntity<JcaKeyGenerateRequest> httpRequest) throws OperatorCreationException {
        JcaKeyGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getFormat() == KeyFormat.EC) {
            if (request.getSize() != 256 && request.getSize() != 384) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        } else if (request.getFormat() == KeyFormat.RSA) {
            if (request.getSize() != 1024 && request.getSize() != 2048) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        JcaKeyGenerateResponse response = this.keyService.generate(request);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/yubico/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<YubicoKeyGenerateResponse> yubicoGenerate(RequestEntity<YubicoKeyGenerateRequest> httpRequest) throws ApduException, IOException, ApplicationNotAvailableException, BadResponseException {
        YubicoKeyGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getManagementKey() == null || request.getManagementKey().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getFormat() == KeyFormat.EC) {
            if (request.getSize() != 256 && request.getSize() != 384) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        } else if (request.getFormat() == KeyFormat.RSA) {
            if (request.getSize() != 1024 && request.getSize() != 2048) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getSerialNumber() == null || request.getSerialNumber().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getSlot() == null || request.getSlot().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        } else {
            Slot pivSlot = null;
            for (Slot slot : Slot.values()) {
                if (slot.getStringAlias().equalsIgnoreCase(request.getSlot())) {
                    pivSlot = slot;
                    break;
                }
            }
            if (pivSlot == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        }

        YubiKeyDevice device = YubicoProviderUtils.lookupDevice(request.getSerialNumber());
        if (device == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        YubicoKeyGenerateResponse response = this.keyService.generate(request);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/yubico/register", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<YubicoKeyRegisterResponse> yubicoRegister(RequestEntity<YubicoKeyRegisterRequest> httpRequest) throws IOException, BadResponseException, ApduException, ApplicationNotAvailableException {
        YubicoKeyRegisterRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getSerialNumber() == null || request.getSerialNumber().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getPin() == null || request.getPin().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getManagementKey() == null || request.getManagementKey().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getSlot() == null || request.getSlot().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        } else {
            Slot pivSlot = null;
            for (Slot slot : Slot.values()) {
                if (slot.getStringAlias().equalsIgnoreCase(request.getSlot())) {
                    pivSlot = slot;
                    break;
                }
            }
            if (pivSlot == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        }

        YubiKeyDevice device = YubicoProviderUtils.lookupDevice(request.getSerialNumber());
        if (device == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        YubicoKeyRegisterResponse response = this.keyService.register(request);
        return ResponseEntity.ok(response);
    }

}
