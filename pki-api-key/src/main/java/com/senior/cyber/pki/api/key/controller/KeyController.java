package com.senior.cyber.pki.api.key.controller;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.x509.KeyFormat;
import com.senior.cyber.pki.common.x509.OpenSshPrivateKeyUtils;
import com.senior.cyber.pki.common.x509.PrivateKeyUtils;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.KeyService;
import com.senior.cyber.pki.service.util.YubicoProviderUtils;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.Slot;
import org.bouncycastle.operator.OperatorCreationException;
import org.jasypt.util.text.AES256TextEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

@RestController
public class KeyController {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyController.class);

    @Autowired
    protected KeyService keyService;

    @Autowired
    protected KeyRepository keyRepository;

    @RequestMapping(path = "/info", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<KeyInfoResponse> info(RequestEntity<KeyInfoRequest> httpRequest) throws OperatorCreationException, IOException {
        KeyInfoRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not found"));
        if (key.getStatus() == KeyStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key have been revoked");
        }

        KeyInfoResponse response = new KeyInfoResponse();
        if (key.getType() != null) {
            response.setType(key.getType().name());
        }
        if (key.getKeyFormat() != null) {
            response.setKeyFormat(key.getKeyFormat().name());
        }
        if (key.getType() == KeyTypeEnum.ServerKeyJCE) {
            if (key.getPrivateKey() != null && !key.getPrivateKey().isEmpty()) {
                PrivateKey privateKey = PrivateKeyUtils.convert(key.getPrivateKey(), request.getKeyPassword());
                response.setPrivateKey(PrivateKeyUtils.convert(privateKey));
                response.setOpenSshPrivateKey(OpenSshPrivateKeyUtils.convert(privateKey));
            }
        } else if (key.getType() == KeyTypeEnum.ServerKeyYubico) {
            if (key.getPrivateKey() != null && !key.getPrivateKey().isEmpty()) {
                AES256TextEncryptor encryptor = new AES256TextEncryptor();
                encryptor.setPassword(request.getKeyPassword());
                String privateKey = encryptor.decrypt(key.getPrivateKey());
                response.setPrivateKey(privateKey);
            }
        }
        PublicKey publicKey = key.getPublicKey();
        response.setPublicKey(publicKey);
        response.setOpenSshPublicKey(publicKey);
        response.setCreatedDatetime(key.getCreatedDatetime());
        if (key.getKeySize() > 0) {
            response.setKeySize(key.getKeySize());
        }
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/jca/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<KeyGenerateResponse> jcaGenerate(RequestEntity<JcaKeyGenerateRequest> httpRequest) throws OperatorCreationException {
        JcaKeyGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getFormat() == KeyFormat.EC) {
            if (request.getSize() != 256 && request.getSize() != 384) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size is not number of [256, 384]");
            }
        } else if (request.getFormat() == KeyFormat.RSA) {
            if (request.getSize() != 1024 && request.getSize() != 2048) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size is not number of [1024, 2048]");
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key format is not type of [" + KeyFormat.EC.name() + ", " + KeyFormat.RSA.name() + "]");
        }

        KeyGenerateResponse response = this.keyService.generate(request);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/yubico/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<KeyGenerateResponse> yubicoGenerate(RequestEntity<YubicoKeyGenerateRequest> httpRequest) throws ApduException, IOException, ApplicationNotAvailableException, BadResponseException {
        YubicoKeyGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getManagementKey() == null || request.getManagementKey().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "management key is required");
        }

        if (request.getFormat() == KeyFormat.EC) {
            if (request.getSize() != 256 && request.getSize() != 384) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size is not number of [256, 384]");
            }
        } else if (request.getFormat() == KeyFormat.RSA) {
            if (request.getSize() != 1024 && request.getSize() != 2048) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size is not number of [1024, 2048]");
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key format is not type of [" + KeyFormat.EC.name() + ", " + KeyFormat.RSA.name() + "]");
        }

        if (request.getSerialNumber() == null || request.getSerialNumber().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "serial number is required");
        }

        if (request.getSlot() == null || request.getSlot().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "slot is required");
        } else {
            Slot pivSlot = null;
            for (Slot slot : Slot.values()) {
                if (slot.getStringAlias().equalsIgnoreCase(request.getSlot())) {
                    pivSlot = slot;
                    break;
                }
            }
            if (pivSlot == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "slot is not found");
            }
        }

        YubiKeyDevice device = YubicoProviderUtils.lookupDevice(request.getSerialNumber());
        if (device == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "device is not found");
        }

        KeyGenerateResponse response = this.keyService.generate(request);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/yubico/register", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<KeyGenerateResponse> yubicoRegister(RequestEntity<YubicoKeyRegisterRequest> httpRequest) throws IOException, BadResponseException, ApduException, ApplicationNotAvailableException {
        YubicoKeyRegisterRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getSerialNumber() == null || request.getSerialNumber().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "serial number is required");
        }

        if (request.getPin() == null || request.getPin().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "pin is required");
        }

        if (request.getManagementKey() == null || request.getManagementKey().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "management key is required");
        }

        if (request.getSlot() == null || request.getSlot().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "slot is required");
        } else {
            Slot pivSlot = null;
            for (Slot slot : Slot.values()) {
                if (slot.getStringAlias().equalsIgnoreCase(request.getSlot())) {
                    pivSlot = slot;
                    break;
                }
            }
            if (pivSlot == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "slot is not found");
            }
        }

        YubiKeyDevice device = YubicoProviderUtils.lookupDevice(request.getSerialNumber());
        if (device == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "device is not found");
        }

        KeyGenerateResponse response = this.keyService.register(request);
        return ResponseEntity.ok(response);
    }

}
