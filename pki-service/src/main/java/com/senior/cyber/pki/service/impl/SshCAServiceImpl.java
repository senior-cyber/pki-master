package com.senior.cyber.pki.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.SshGenerateRequest;
import com.senior.cyber.pki.common.dto.SshGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoPassword;
import com.senior.cyber.pki.common.x509.PrivateKeyUtils;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.SshCAService;
import com.senior.cyber.pki.service.Utils;
import com.senior.cyber.pki.service.util.YubicoProviderUtils;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.jca.PivProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.jasypt.util.text.AES256TextEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;

@Service
public class SshCAServiceImpl implements SshCAService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SshCAServiceImpl.class);

    @Autowired
    protected KeyRepository keyRepository;

    @Autowired
    protected ObjectMapper objectMapper;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public SshGenerateResponse sshcaGenerate(SshGenerateRequest request) throws OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        Key _issuerKey = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));

        SmartCardConnection connection = null;
        try {
            KeyPair issuerKey = null;
            Provider issuerProvider = null;
            switch (_issuerKey.getType()) {
                case ServerKeyJCE -> {
                    issuerProvider = Utils.BC;
                    issuerKey = new KeyPair(_issuerKey.getPublicKey(), PrivateKeyUtils.convert(_issuerKey.getPrivateKey(), request.getKeyPassword()));
                }
                case ServerKeyYubico -> {
                    AES256TextEncryptor encryptor = new AES256TextEncryptor();
                    encryptor.setPassword(request.getKeyPassword());
                    YubicoPassword yubicoIssuer = this.objectMapper.readValue(encryptor.decrypt(_issuerKey.getPrivateKey()), YubicoPassword.class);

                    YubiKeyDevice device = YubicoProviderUtils.lookupDevice(yubicoIssuer.getSerial());
                    if (device == null) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "device not found");
                    }
                    connection = device.openConnection(SmartCardConnection.class);
                    PivSession session = new PivSession(connection);
                    session.authenticate(YubicoProviderUtils.hexStringToByteArray(yubicoIssuer.getManagementKey()));
                    issuerProvider = new PivProvider(session);
                    KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider);
                    Slot slot = null;
                    for (Slot s : Slot.values()) {
                        if (s.getStringAlias().equalsIgnoreCase(yubicoIssuer.getPivSlot())) {
                            slot = s;
                            break;
                        }
                    }
                    PrivateKey issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, slot, yubicoIssuer.getPin());
                    issuerKey = new KeyPair(_issuerKey.getPublicKey(), issuerPrivateKey);
                }
            }

            SshGenerateResponse response = new SshGenerateResponse();
            response.setKeyId(request.getKeyId());
            response.setKeyPassword(request.getKeyPassword());
            response.setSshCa(issuerKey.getPublic());
            return response;
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }

}
