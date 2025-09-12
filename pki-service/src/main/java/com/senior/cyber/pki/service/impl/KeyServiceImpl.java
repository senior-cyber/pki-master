package com.senior.cyber.pki.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.x509.KeyFormat;
import com.senior.cyber.pki.common.x509.KeyUtils;
import com.senior.cyber.pki.common.x509.PrivateKeyUtils;
import com.senior.cyber.pki.common.x509.Yubico;
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
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.jasypt.util.text.AES256TextEncryptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Date;

@Service
public class KeyServiceImpl implements KeyService {

    @Autowired
    private KeyRepository keyRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public KeyGenerateResponse generate(JcaKeyGenerateRequest request) throws OperatorCreationException {
        String password = RandomStringUtils.secureStrong().nextAlphanumeric(20);
        KeyPair _key = KeyUtils.generate(request.getFormat(), request.getSize());
        Key key = new Key();
        key.setStatus(KeyStatusEnum.Good);
        key.setPrivateKey(PrivateKeyUtils.convert(_key.getPrivate(), password));
        key.setPublicKey(_key.getPublic());
        key.setType(KeyTypeEnum.ServerKeyJCE);
        key.setKeySize(request.getSize());
        key.setKeyFormat(request.getFormat());
        key.setCreatedDatetime(new Date());
        this.keyRepository.save(key);

        KeyGenerateResponse response = new KeyGenerateResponse();
        response.setKeyPassword(password);
        response.setKeyId(key.getId());
        return response;
    }

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public KeyGenerateResponse generate(YubicoKeyGenerateRequest request) throws ApduException, IOException, ApplicationNotAvailableException, BadResponseException {
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

            YubicoPassword yubicoPassword = new YubicoPassword();
            yubicoPassword.setPin(Yubico.DEFAULT_PIN);
            yubicoPassword.setManagementKey(request.getManagementKey());
            if (pivSlot != null) {
                yubicoPassword.setPivSlot(pivSlot.getStringAlias());
            }
            yubicoPassword.setSerial(request.getSerialNumber());

            Key key = new Key();
            key.setStatus(KeyStatusEnum.Good);
            key.setPublicKey(publicKey);
            key.setType(KeyTypeEnum.ServerKeyYubico);
            key.setKeySize(request.getSize());
            key.setPrivateKey(encryptor.encrypt(objectMapper.writeValueAsString(yubicoPassword)));
            key.setKeyFormat(request.getFormat());
            key.setCreatedDatetime(new Date());
            this.keyRepository.save(key);

            KeyGenerateResponse response = new KeyGenerateResponse();
            response.setKeyId(key.getId());
            response.setKeyPassword(password);
            return response;
        }
    }

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public KeyGenerateResponse register(YubicoKeyRegisterRequest request) throws IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
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
            PublicKey publicKey = YubicoProviderUtils.lookupPublicKey(session, pivSlot);

            String password = RandomStringUtils.secureStrong().nextAlphanumeric(20);
            AES256TextEncryptor encryptor = new AES256TextEncryptor();
            encryptor.setPassword(password);

            YubicoPassword yubicoPassword = new YubicoPassword();
            yubicoPassword.setPin(request.getPin());
            yubicoPassword.setManagementKey(request.getManagementKey());
            if (pivSlot != null) {
                yubicoPassword.setPivSlot(pivSlot.getStringAlias());
            }
            yubicoPassword.setSerial(request.getSerialNumber());

            Key key = new Key();
            key.setStatus(KeyStatusEnum.Good);
            key.setPublicKey(publicKey);
            key.setType(KeyTypeEnum.ServerKeyYubico);
            if (publicKey instanceof RSAKey) {
                key.setKeyFormat(KeyFormat.RSA);
            } else if (publicKey instanceof ECKey) {
                key.setKeyFormat(KeyFormat.EC);
            }
            key.setPrivateKey(encryptor.encrypt(objectMapper.writeValueAsString(yubicoPassword)));
            key.setCreatedDatetime(new Date());
            this.keyRepository.save(key);

            KeyGenerateResponse response = new KeyGenerateResponse();
            response.setKeyId(key.getId());
            response.setKeyPassword(password);
            return response;
        }
    }

}
