package com.senior.cyber.pki.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.util.YubicoProviderUtils;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.common.dto.KeyStatusEnum;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.KeyService;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.jasypt.util.text.AES256TextEncryptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Date;

@Service
@Slf4j
public class KeyServiceImpl implements KeyService {

    @Autowired
    private KeyRepository keyRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public KeyGenerateResponse bcGenerate(BcGenerateRequest request) throws OperatorCreationException, JsonProcessingException {
        log.debug("BcGenerateRequest [{}]", this.objectMapper.writeValueAsString(request));
        String password = RandomStringUtils.secureStrong().nextAlphanumeric(20);
        KeyPair _key = KeyUtils.generate(request.getFormat(), request.getSize());
        Key key = new Key();
        key.setStatus(KeyStatusEnum.Good);
        key.setPrivateKey(PrivateKeyUtils.convert(_key.getPrivate(), password));
        key.setPublicKey(_key.getPublic());
        key.setType(KeyTypeEnum.BC);
        key.setKeySize(request.getSize());
        key.setKeyFormat(request.getFormat());
        key.setEmailAddress(request.getEmailAddress());
        key.setCreatedDatetime(new Date());
        this.keyRepository.save(key);

        KeyGenerateResponse response = KeyGenerateResponse.builder()
                .keyPassword(password)
                .keyId(key.getId()).build();
        if (key.getKeyFormat() == KeyFormatEnum.RSA) {
            response.setOpenSshPublicKey(key.getPublicKey());
        }
        log.debug("KeyGenerateResponse [{}]", this.objectMapper.writeValueAsString(response));
        return response;
    }

    @Override
    public KeyGenerateResponse bcRegister(BcRegisterRequest request) throws JsonProcessingException {
        log.debug("BcRegisterRequest [{}]", this.objectMapper.writeValueAsString(request));
        Key key = new Key();
        key.setStatus(KeyStatusEnum.Good);
        key.setPrivateKey(null);
        key.setPublicKey(request.getPublicKey());
        key.setType(KeyTypeEnum.BC);
        key.setKeySize(request.getSize());
        key.setKeyFormat(request.getFormat());
        key.setCreatedDatetime(new Date());
        key.setEmailAddress(request.getEmailAddress());
        this.keyRepository.save(key);

        KeyGenerateResponse response = KeyGenerateResponse.builder()
                .keyId(key.getId()).build();
        if (key.getKeyFormat() == KeyFormatEnum.RSA) {
            response.setOpenSshPublicKey(key.getPublicKey());
        }
        log.debug("KeyGenerateResponse [{}]", this.objectMapper.writeValueAsString(response));
        return response;
    }

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public KeyGenerateResponse yubicoGenerate(YubicoGenerateRequest request) throws ApduException, IOException, ApplicationNotAvailableException, BadResponseException {
        log.debug("YubicoGenerateRequest [{}]", this.objectMapper.writeValueAsString(request));
        Slot pivSlot = null;
        for (Slot slot : Slot.values()) {
            if (slot.getStringAlias().equalsIgnoreCase(request.getSlot())) {
                pivSlot = slot;
                break;
            }
        }
        YubiKeyDevice device = YubicoProviderUtils.lookupDevice(request.getSerialNumber());
        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            PivSession session = new PivSession(connection);
            session.authenticate(YubicoProviderUtils.hexStringToByteArray(request.getManagementKey()));
            PublicKey publicKey = null;
            switch (request.getFormat()) {
                case RSA -> {
                    switch (request.getSize()) {
                        case 1024 -> {
                            publicKey = YubicoProviderUtils.generateKey(session, pivSlot, KeyType.RSA1024);
                        }
                        case 2048 -> {
                            publicKey = YubicoProviderUtils.generateKey(session, pivSlot, KeyType.RSA2048);
                        }
                    }
                }
                case EC -> {
                    switch (request.getSize()) {
                        case 256 -> {
                            publicKey = YubicoProviderUtils.generateKey(session, pivSlot, KeyType.ECCP256);
                        }
                        case 384 -> {
                            publicKey = YubicoProviderUtils.generateKey(session, pivSlot, KeyType.ECCP384);
                        }
                    }
                }
            }

            String password = RandomStringUtils.secureStrong().nextAlphanumeric(20);
            AES256TextEncryptor encryptor = new AES256TextEncryptor();
            encryptor.setPassword(password);

            YubicoPassword yubicoPassword = YubicoPassword.builder()
                    .pin(Yubico.DEFAULT_PIN).build();
            yubicoPassword.setManagementKey(request.getManagementKey());
            if (pivSlot != null) {
                yubicoPassword.setPivSlot(pivSlot.getStringAlias());
            }
            yubicoPassword.setSerial(request.getSerialNumber());

            Key key = new Key();
            key.setStatus(KeyStatusEnum.Good);
            key.setPublicKey(publicKey);
            key.setType(KeyTypeEnum.Yubico);
            key.setKeySize(request.getSize());
            key.setPrivateKey(encryptor.encrypt(objectMapper.writeValueAsString(yubicoPassword)));
            key.setKeyFormat(request.getFormat());
            key.setEmailAddress(request.getEmailAddress());
            key.setCreatedDatetime(new Date());
            this.keyRepository.save(key);

            KeyGenerateResponse response = KeyGenerateResponse.builder().build();
            response.setKeyId(key.getId());
            response.setKeyPassword(password);
            if (key.getKeyFormat() == KeyFormatEnum.RSA) {
                response.setOpenSshPublicKey(key.getPublicKey());
            }
            log.debug("KeyGenerateResponse [{}]", this.objectMapper.writeValueAsString(response));
            return response;
        }
    }

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public KeyGenerateResponse yubicoRegister(YubicoRegisterRequest request) throws IOException {
        log.debug("YubicoRegisterRequest [{}]", this.objectMapper.writeValueAsString(request));
        Slot pivSlot = null;
        for (Slot slot : Slot.values()) {
            if (slot.getStringAlias().equalsIgnoreCase(request.getSlot())) {
                pivSlot = slot;
                break;
            }
        }

        String password = RandomStringUtils.secureStrong().nextAlphanumeric(20);
        AES256TextEncryptor encryptor = new AES256TextEncryptor();
        encryptor.setPassword(password);

        YubicoPassword yubicoPassword = YubicoPassword.builder().build();
        yubicoPassword.setPin(request.getPin());
        yubicoPassword.setManagementKey(request.getManagementKey());
        if (pivSlot != null) {
            yubicoPassword.setPivSlot(pivSlot.getStringAlias());
        }
        yubicoPassword.setSerial(request.getSerialNumber());

        Key key = new Key();
        key.setStatus(KeyStatusEnum.Good);
        key.setPublicKey(request.getPublicKey());
        key.setType(KeyTypeEnum.Yubico);
        key.setKeySize(request.getSize());
        key.setKeyFormat(request.getFormat());
        key.setPrivateKey(encryptor.encrypt(objectMapper.writeValueAsString(yubicoPassword)));
        key.setEmailAddress(request.getEmailAddress());
        key.setCreatedDatetime(new Date());
        this.keyRepository.save(key);

        log.debug("DEBUG yubico register key [{}]", key.getId());

        KeyGenerateResponse response = KeyGenerateResponse.builder().build();
        response.setKeyId(key.getId());
        response.setKeyPassword(password);
        if (key.getKeyFormat() == KeyFormatEnum.RSA) {
            response.setOpenSshPublicKey(key.getPublicKey());
        }
        log.debug("KeyGenerateResponse [{}]", this.objectMapper.writeValueAsString(response));
        return response;
    }

}
