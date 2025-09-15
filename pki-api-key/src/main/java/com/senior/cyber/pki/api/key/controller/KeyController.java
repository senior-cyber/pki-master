package com.senior.cyber.pki.api.key.controller;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.util.YubicoProviderUtils;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.KeyService;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.Slot;
import org.bouncycastle.operator.OperatorCreationException;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
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
import java.security.*;

@RestController
public class KeyController {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyController.class);

    @Autowired
    protected KeyService keyService;

    @Autowired
    protected KeyRepository keyRepository;

    @RequestMapping(path = "/download", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<KeyDownloadResponse> download(RequestEntity<KeyDownloadRequest> httpRequest) throws OperatorCreationException, IOException {
        KeyDownloadRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not found"));
        if (key.getStatus() == KeyStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key have been revoked");
        }

        KeyDownloadResponse response = new KeyDownloadResponse();
        response.setType(key.getType());
        response.setKeyFormat(key.getKeyFormat());
        if (key.getType() == KeyTypeEnum.BC) {
            if (key.getPrivateKey() != null && !key.getPrivateKey().isEmpty()) {
                PrivateKey privateKey = PrivateKeyUtils.convert(key.getPrivateKey(), request.getKeyPassword());
                response.setPrivateKey(PrivateKeyUtils.convert(privateKey));
                response.setOpenSshPrivateKey(OpenSshPrivateKeyUtils.convert(privateKey));
            }
        } else if (key.getType() == KeyTypeEnum.Yubico) {
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

    @RequestMapping(path = "/info", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<KeyInfoResponse> info(RequestEntity<KeyInfoRequest> httpRequest) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, OperatorCreationException {
        KeyInfoRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not found"));
        if (key.getStatus() == KeyStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key have been revoked");
        }

        KeyInfoResponse response = new KeyInfoResponse();

        response.setType(key.getType());
        switch (key.getType()) {
            case BC -> {
                if (key.getPrivateKey() == null || key.getPrivateKey().isEmpty()) {
                    if (!PublicKeyUtils.verifyText(key.getPublicKey(), request.getKeyPassword() + "." + key.getId())) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
                    }
                } else {
                    if (PrivateKeyUtils.convert(key.getPrivateKey(), request.getKeyPassword()) == null) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
                    }
                }
                response.setDecentralized(key.getPrivateKey() == null || key.getPrivateKey().isEmpty());
            }
            case Yubico -> {
                AES256TextEncryptor encryptor = new AES256TextEncryptor();
                encryptor.setPassword(request.getKeyPassword());
                try {
                    encryptor.decrypt(key.getPrivateKey());
                } catch (EncryptionOperationNotPossibleException | EncryptionInitializationException e) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
                }
                response.setDecentralized(true);
            }
        }

        if (key.getKeyFormat() != null) {
            response.setFormat(key.getKeyFormat());
        }
        if (key.getKeySize() > 0) {
            response.setSize(key.getKeySize());
        }
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/bc/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<KeyGenerateResponse> bcGenerate(RequestEntity<KeyBcGenerateRequest> httpRequest) throws OperatorCreationException {

        KeyBcGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getFormat() == KeyFormatEnum.EC) {
            if (request.getSize() != 256 && request.getSize() != 384) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size is not number of [256, 384]");
            }
        } else if (request.getFormat() == KeyFormatEnum.RSA) {
            if (request.getSize() != 1024 && request.getSize() != 2048) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size is not number of [1024, 2048]");
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key format is not type of [" + KeyFormatEnum.EC.name() + ", " + KeyFormatEnum.RSA.name() + "]");
        }

        KeyGenerateResponse response = this.keyService.bcGenerate(request);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/bc/register", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<KeyBcClientRegisterResponse> bcClientRegister(RequestEntity<KeyBcClientRegisterRequest> httpRequest) throws OperatorCreationException {
        KeyBcClientRegisterRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getFormat() == KeyFormatEnum.EC) {
            if (request.getSize() != 256 && request.getSize() != 384) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size is not number of [256, 384]");
            }
        } else if (request.getFormat() == KeyFormatEnum.RSA) {
            if (request.getSize() != 1024 && request.getSize() != 2048) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size is not number of [1024, 2048]");
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key format is not type of [" + KeyFormatEnum.EC.name() + ", " + KeyFormatEnum.RSA.name() + "]");
        }

        if (request.getPublicKey() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "public key is null");
        }
        KeyBcClientRegisterResponse response = this.keyService.bcRegister(request);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/yubico/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<KeyGenerateResponse> yubicoGenerate(RequestEntity<YubicoGenerateRequest> httpRequest) throws ApduException, IOException, ApplicationNotAvailableException, BadResponseException {
        YubicoGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getManagementKey() == null || request.getManagementKey().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "management key is required");
        }

        if (request.getFormat() == KeyFormatEnum.EC) {
            if (request.getSize() != 256 && request.getSize() != 384) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size is not number of [256, 384]");
            }
        } else if (request.getFormat() == KeyFormatEnum.RSA) {
            if (request.getSize() != 1024 && request.getSize() != 2048) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size is not number of [1024, 2048]");
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key format is not type of [" + KeyFormatEnum.EC.name() + ", " + KeyFormatEnum.RSA.name() + "]");
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

        KeyGenerateResponse response = this.keyService.yubicoGenerate(request);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/yubico/register", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<KeyGenerateResponse> yubicoRegister(RequestEntity<YubicoRegisterRequest> httpRequest) throws IOException, BadResponseException, ApduException, ApplicationNotAvailableException {
        YubicoRegisterRequest request = httpRequest.getBody();
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

        if (request.getPublicKey() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "public key is null");
        }

        KeyGenerateResponse response = this.keyService.yubicoRegister(request);
        return ResponseEntity.ok(response);
    }

}
