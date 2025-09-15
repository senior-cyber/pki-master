package com.senior.cyber.pki.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.SshClientGenerateRequest;
import com.senior.cyber.pki.common.dto.SshClientGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoPassword;
import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import com.senior.cyber.pki.common.x509.PrivateKeyUtils;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.SshCAService;
import com.senior.cyber.pki.service.Utils;
import com.senior.cyber.pki.common.util.Crypto;
import com.senior.cyber.pki.service.util.OpenSshCertificateBuilder;
import com.senior.cyber.pki.common.util.PivUtils;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.jca.PivProvider;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.jasypt.util.text.AES256TextEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.Duration;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class SshCAServiceImpl implements SshCAService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SshCAServiceImpl.class);

    @Autowired
    protected KeyRepository keyRepository;

    @Autowired
    protected ObjectMapper objectMapper;

    @Override
    @Transactional
    public SshClientGenerateResponse sshClientGenerate(SshClientGenerateRequest request) throws Exception {
        Map<String, SmartCardConnection> connections = new HashMap<>();
        Map<String, KeyStore> keys = new HashMap<>();
        Map<String, PivProvider> providers = new HashMap<>();
        Map<String, PivSession> sessions = new HashMap<>();
        Map<String, Slot> slots = new HashMap<>();
        Map<String, String> serials = new HashMap<>();

        Key issuerKey = this.keyRepository.findById(request.getIssuer().getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));
        if (issuerKey.getKeyFormat() != KeyFormatEnum.RSA) {
            LOGGER.info("issuer key format type is {}", issuerKey.getType());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "issuer key format is not type of [" + KeyFormatEnum.RSA.name() + "]");
        }

        Crypto issuer = null;
        switch (issuerKey.getType()) {
            case BC -> {
                PrivateKey privateKey = PrivateKeyUtils.convert(issuerKey.getPrivateKey(), request.getIssuer().getKeyPassword());
                issuer = new Crypto(Utils.BC, issuerKey.getPublicKey(), privateKey);
            }
            case Yubico -> {
                AES256TextEncryptor encryptor = new AES256TextEncryptor();
                encryptor.setPassword(request.getIssuer().getKeyPassword());
                YubicoPassword yubico = this.objectMapper.readValue(encryptor.decrypt(issuerKey.getPrivateKey()), YubicoPassword.class);
                PrivateKey privateKey = PivUtils.lookupPrivateKey(providers, connections, sessions, slots, serials, keys, issuerKey.getId(), yubico);
                issuer = new Crypto(providers.get(serials.get(issuerKey.getId())), issuerKey.getPublicKey(), privateKey);
            }
        }

        if ((request.getPrincipal() == null || request.getPrincipal().isEmpty())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "principal required");
        }

        try {
            Key sshKey = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not found"));
            Crypto ssh = null;
            if (sshKey.getKeyFormat() != KeyFormatEnum.RSA) {
                LOGGER.info("issuer key format type is {}", sshKey.getType());
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key format is not type of [" + KeyFormatEnum.RSA.name() + "]");
            }

            switch (sshKey.getType()) {
                case BC -> {
                    PrivateKey privateKey = PrivateKeyUtils.convert(sshKey.getPrivateKey(), request.getKeyPassword());
                    ssh = new Crypto(Utils.BC, issuerKey.getPublicKey(), privateKey);
                }
                case Yubico -> {
                    AES256TextEncryptor encryptor = new AES256TextEncryptor();
                    encryptor.setPassword(request.getKeyPassword());
                    YubicoPassword yubico = this.objectMapper.readValue(encryptor.decrypt(sshKey.getPrivateKey()), YubicoPassword.class);
                    PrivateKey privateKey = PivUtils.lookupPrivateKey(providers, connections, sessions, slots, serials, keys, sshKey.getId(), yubico);
                    ssh = new Crypto(providers.get(serials.get(sshKey.getId())), sshKey.getPublicKey(), privateKey);
                }
            }

            OpenSshCertificateBuilder openSshCertificateBuilder = OpenSshCertificateBuilder.userCertificate();
            openSshCertificateBuilder.provider(issuer.getProvider());
            openSshCertificateBuilder.id(UUID.randomUUID().toString());
            openSshCertificateBuilder.serial(System.currentTimeMillis());
            openSshCertificateBuilder.extensions(Arrays.asList(
                    new OpenSshCertificate.CertificateOption("permit-user-rc"),
                    new OpenSshCertificate.CertificateOption("permit-X11-forwarding"),
                    new OpenSshCertificate.CertificateOption("permit-agent-forwarding"),
                    new OpenSshCertificate.CertificateOption("permit-port-forwarding"),
                    new OpenSshCertificate.CertificateOption("permit-pty")));
            openSshCertificateBuilder.principals(List.of(request.getPrincipal()));
            openSshCertificateBuilder.publicKey(ssh.getPublicKey());
            openSshCertificateBuilder.validAfter(Instant.now());

            Duration duration = DatatypeFactory.newInstance().newDuration(request.getPeriod());
            openSshCertificateBuilder.validBefore(Instant.now()
                    .plus(duration.getYears(), ChronoUnit.YEARS)
                    .plus(duration.getMonths(), ChronoUnit.MONTHS)
                    .plus(duration.getDays(), ChronoUnit.DAYS)
                    .plus(duration.getHours(), ChronoUnit.HOURS)
                    .plus(duration.getMinutes(), ChronoUnit.MINUTES)
                    .plus(duration.getSeconds(), ChronoUnit.SECONDS)
            );

            OpenSshCertificate certificate = openSshCertificateBuilder.sign(new KeyPair(issuer.getPublicKey(), issuer.getPrivateKey()), org.apache.sshd.common.config.keys.KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS);
            SshClientGenerateResponse response = new SshClientGenerateResponse();
            response.setOpenSshPublicKey(ssh.getPublicKey());
            response.setOpenSshCertificate(certificate);
            switch (sshKey.getType()) {
                case BC -> {
                    response.setOpenSshPrivateKey(ssh.getPrivateKey());
                    response.setConfig("Host " + request.getAlias() + "\n" +
                            "    HostName " + request.getServer() + "\n" +
                            "    User " + request.getPrincipal() + "\n" +
                            "    IdentityFile id_rsa\n" +
                            "    CertificateFile id_rsa-cert.pub");
                }
                case Yubico -> {
                    response.setConfig("Host " + request.getAlias() + "\n" +
                            "    HostName " + request.getServer() + "\n" +
                            "    User " + request.getPrincipal() + "\n" +
                            "    PKCS11Provider /usr/local/lib/libykcs11.so\n" +
                            "    IdentityFile id_rsa.pub\n" +
                            "    CertificateFile id_rsa-cert.pub");
                }
            }
            return response;
        } finally {
            for (SmartCardConnection connection : connections.values()) {
                if (connection != null) {
                    connection.close();
                }
            }
        }
    }

}
