package com.senior.cyber.pki.service.impl;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.x509.KeyFormat;
import com.senior.cyber.pki.common.x509.KeyUtils;
import com.senior.cyber.pki.common.x509.Yubico;
import com.senior.cyber.pki.dao.entity.pki.Key;
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

    @Override
    @Transactional
    public JcaKeyGenerateResponse generate(JcaKeyGenerateRequest request) {
        KeyPair _key = KeyUtils.generate(request.getFormat(), request.getSize());
        Key key = new Key();
        key.setPrivateKey(_key.getPrivate());
        key.setPublicKey(_key.getPublic());
        key.setType(KeyTypeEnum.ServerKeyJCE);
        key.setPassword(request.getPassword());
        key.setKeySize(request.getSize());
        key.setKeyFormat(request.getFormat());
        key.setCreatedDatetime(new Date());
        this.keyRepository.save(key);

        JcaKeyGenerateResponse response = new JcaKeyGenerateResponse();
        response.setId(key.getId());
        return response;
    }

    @Override
    @Transactional
    public YubicoKeyGenerateResponse generate(YubicoKeyGenerateRequest request) throws ApduException, IOException, ApplicationNotAvailableException, BadResponseException {
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
            if (request.getFormat() == KeyFormat.RSA) {
                if (request.getSize() == 1024) {
                    publicKey = YubicoProviderUtils.generateKey(session, pivSlot, KeyType.RSA1024);
                } else if (request.getSize() == 2048) {
                    publicKey = YubicoProviderUtils.generateKey(session, pivSlot, KeyType.RSA2048);
                }
            } else if (request.getFormat() == KeyFormat.EC) {
                if (request.getSize() == 256) {
                    publicKey = YubicoProviderUtils.generateKey(session, pivSlot, KeyType.ECCP256);
                } else if (request.getSize() == 384) {
                    publicKey = YubicoProviderUtils.generateKey(session, pivSlot, KeyType.ECCP384);
                }
            }

            Key key = new Key();
            key.setPublicKey(publicKey);
            key.setType(KeyTypeEnum.ServerKeyYubico);
            key.setKeySize(request.getSize());
            key.setYubicoSerial(request.getSerialNumber());
            key.setYubicoPivSlot(pivSlot.getStringAlias());
            key.setYubicoManagementKey(request.getManagementKey());
            key.setYubicoPin(Yubico.DEFAULT_PIN);
            key.setKeyFormat(request.getFormat());
            key.setCreatedDatetime(new Date());
            this.keyRepository.save(key);

            YubicoKeyGenerateResponse response = new YubicoKeyGenerateResponse();
            response.setId(key.getId());
            return response;
        }
    }

    @Override
    @Transactional
    public JcaKeyRegisterResponse register(JcaKeyRegisterRequest request) {
        Key key = new Key();
        key.setPublicKey(request.getPublicKey());
        key.setPrivateKey(request.getPrivateKey());
        if (request.getPrivateKey() == null) {
            key.setType(KeyTypeEnum.ClientKey);
        } else {
            key.setType(KeyTypeEnum.ServerKeyJCE);
        }
        if (request.getPublicKey() instanceof RSAKey) {
            key.setKeyFormat(KeyFormat.RSA);
        } else if (request.getPublicKey() instanceof ECKey) {
            key.setKeyFormat(KeyFormat.EC);
        }
        key.setCreatedDatetime(new Date());
        this.keyRepository.save(key);

        JcaKeyRegisterResponse response = new JcaKeyRegisterResponse();
        response.setId(key.getId());
        return response;
    }

    @Override
    public YubicoKeyRegisterResponse register(YubicoKeyRegisterRequest request) throws IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
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


            Key key = new Key();
            key.setPublicKey(publicKey);
            key.setType(KeyTypeEnum.ServerKeyYubico);
            if (publicKey instanceof RSAKey) {
                key.setKeyFormat(KeyFormat.RSA);
            } else if (publicKey instanceof ECKey) {
                key.setKeyFormat(KeyFormat.EC);
            }
            key.setYubicoManagementKey(request.getManagementKey());
            key.setYubicoPin(request.getPin());
            key.setYubicoPivSlot(pivSlot.getStringAlias());
            key.setYubicoSerial(request.getSerialNumber());
            key.setCreatedDatetime(new Date());
            this.keyRepository.save(key);

            YubicoKeyRegisterResponse response = new YubicoKeyRegisterResponse();
            response.setId(key.getId());
            return response;
        }
    }

}
