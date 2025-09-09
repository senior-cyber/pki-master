package com.senior.cyber.pki.service.impl;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.x509.PkiUtils;
import com.senior.cyber.pki.common.x509.PrivateKeyUtils;
import com.senior.cyber.pki.common.x509.SubjectUtils;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.LeafService;
import com.senior.cyber.pki.service.util.OpenSshCertificateBuilder;
import com.senior.cyber.pki.service.util.YubicoProviderUtils;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.jca.PivProvider;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.joda.time.LocalDate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class LeafServiceImpl implements LeafService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Override
    public ServerGenerateResponse serverGenerate(ServerGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        Date _now = LocalDate.now().toDate();

        Certificate _issuerCertificate = this.certificateRepository.findById(request.getIssuer().getCertificateId()).orElseThrow();
        if (_issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (_issuerCertificate.getType() != CertificateTypeEnum.ROOT_CA && _issuerCertificate.getType() != CertificateTypeEnum.SUBORDINATE_CA) ||
                _issuerCertificate.getValidFrom().after(_now) ||
                _issuerCertificate.getValidUntil().before(_now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuer().getCertificateId() + " is not valid");
        }

        X509Certificate issuerCertificate = _issuerCertificate.getCertificate();

        Key issuerKey = this.keyRepository.findById(_issuerCertificate.getKey().getId()).orElseThrow();

        SmartCardConnection connection = null;

        Provider issuerProvider = null;
        PrivateKey issuerPrivateKey = null;
        switch (issuerKey.getType()) {
            case ServerKeyJCE -> {
                issuerProvider = new BouncyCastleProvider();
                issuerPrivateKey = PrivateKeyUtils.convert(issuerKey.getPrivateKey(), request.getIssuer().getKeyPassword());
            }
            case ServerKeyYubico -> {
                YubiKeyDevice device = YubicoProviderUtils.lookupDevice(issuerKey.getYubicoSerial());
                if (device == null) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "device not found");
                }
                connection = device.openConnection(SmartCardConnection.class);
                PivSession session = new PivSession(connection);
                session.authenticate(YubicoProviderUtils.hexStringToByteArray(issuerKey.getYubicoManagementKey()));
                issuerProvider = new PivProvider(session);
                KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider);
                Slot slot = null;
                for (Slot s : Slot.values()) {
                    if (s.getStringAlias().equalsIgnoreCase(issuerKey.getYubicoPivSlot())) {
                        slot = s;
                        break;
                    }
                }
                issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, slot, issuerKey.getYubicoPin());
            }
        }

        try {
            Key certificateKey = this.keyRepository.findById(request.getKeyId()).orElseThrow();
            if (certificateKey.getType() == KeyTypeEnum.ServerKeyYubico) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getKeyId() + " is not support");
            }
            PublicKey publicKey = certificateKey.getPublicKey();

            LocalDate now = LocalDate.now();
            X500Name subject = SubjectUtils.generate(request.getCountry(), request.getOrganization(), request.getOrganizationalUnit(), request.getCommonName(), request.getLocality(), request.getProvince(), request.getEmailAddress());
            List<Integer> keyUsages = new ArrayList<>();
            keyUsages.add(KeyUsage.digitalSignature);
            switch (certificateKey.getKeyFormat()) {
                case RSA -> {
                    keyUsages.add(KeyUsage.keyEncipherment);
                }
                case EC -> {
                    keyUsages.add(KeyUsage.keyEncipherment);
                    keyUsages.add(KeyUsage.keyAgreement);
                }
            }
            List<KeyPurposeId> extendedKeyUsages = new ArrayList<>();
            extendedKeyUsages.add(KeyPurposeId.id_kp_serverAuth);
            List<String> sans = request.getSans();
            X509Certificate leafCertificate = PkiUtils.issueLeafCertificate(issuerProvider, issuerPrivateKey, issuerCertificate, crlApi, ocspApi, x509Api, null, publicKey, subject, now.toDate(), now.plusYears(1).toDate(), System.currentTimeMillis(), keyUsages, extendedKeyUsages, sans);
            Certificate certificate = new Certificate();
            certificate.setIssuerCertificate(_issuerCertificate);
            certificate.setCountryCode(request.getCountry());
            certificate.setOrganization(request.getOrganization());
            certificate.setOrganizationalUnit(request.getOrganizationalUnit());
            certificate.setCommonName(request.getCommonName());
            certificate.setLocalityName(request.getLocality());
            certificate.setStateOrProvinceName(request.getProvince());
            certificate.setEmailAddress(request.getEmailAddress());
            certificate.setKey(certificateKey);
            certificate.setCertificate(leafCertificate);
            certificate.setSerial(leafCertificate.getSerialNumber().longValueExact());
            certificate.setCreatedDatetime(new Date());
            certificate.setValidFrom(leafCertificate.getNotBefore());
            certificate.setValidUntil(leafCertificate.getNotAfter());
            certificate.setStatus(CertificateStatusEnum.Good);
            certificate.setType(CertificateTypeEnum.TLS_SERVER);
            this.certificateRepository.save(certificate);

            ServerGenerateResponse response = new ServerGenerateResponse();
            response.setCertificateId(certificate.getId());
            response.setKeyPassword(request.getKeyPassword());
            response.setCert(leafCertificate);
            response.setPrivkey(PrivateKeyUtils.convert(certificateKey.getPrivateKey(), request.getKeyPassword()));

            List<X509Certificate> chain = new ArrayList<>();
            chain.add(issuerCertificate);

            Certificate temp = _issuerCertificate;
            while (true) {
                String id = temp.getIssuerCertificate().getId();
                Certificate cert = this.certificateRepository.findById(id).orElse(null);
                if (cert == null) {
                    break;
                }
                if (cert.getType() == CertificateTypeEnum.ROOT_CA) {
                    break;
                }
                if (cert.getType() == CertificateTypeEnum.SUBORDINATE_CA) {
                    chain.add(cert.getCertificate());
                    temp = cert;
                }
            }
            response.setChain(chain);

            List<X509Certificate> fullchain = new ArrayList<>();
            fullchain.add(certificate.getCertificate());
            temp = certificate;
            while (true) {
                String id = temp.getIssuerCertificate().getId();
                Certificate cert = this.certificateRepository.findById(id).orElse(null);
                if (cert == null) {
                    break;
                }
                if (cert.getType() == CertificateTypeEnum.ROOT_CA) {
                    break;
                }
                if (cert.getType() == CertificateTypeEnum.SUBORDINATE_CA) {
                    fullchain.add(cert.getCertificate());
                    temp = cert;
                }
            }
            response.setFullchain(fullchain);
            return response;
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }

    @Override
    @Transactional
    public SshClientGenerateResponse sshClientGenerate(SshClientGenerateRequest request) throws Exception {
        Key _issuerKey = this.keyRepository.findById(request.getIssuer().getKeyId()).orElseThrow();

        SmartCardConnection connection = null;

        KeyPair issuerKey = null;
        Provider issuerProvider = null;
        switch (_issuerKey.getType()) {
            case ServerKeyJCE -> {
                issuerProvider = new BouncyCastleProvider();
                issuerKey = new KeyPair(_issuerKey.getPublicKey(), PrivateKeyUtils.convert(_issuerKey.getPrivateKey(), request.getIssuer().getKeyPassword()));
            }
            case ServerKeyYubico -> {
                YubiKeyDevice device = YubicoProviderUtils.lookupDevice(_issuerKey.getYubicoSerial());
                if (device == null) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "device not found");
                }
                connection = device.openConnection(SmartCardConnection.class);
                PivSession session = new PivSession(connection);
                session.authenticate(YubicoProviderUtils.hexStringToByteArray(_issuerKey.getYubicoManagementKey()));
                issuerProvider = new PivProvider(session);
                KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider);
                Slot slot = null;
                for (Slot s : Slot.values()) {
                    if (s.getStringAlias().equalsIgnoreCase(_issuerKey.getYubicoPivSlot())) {
                        slot = s;
                        break;
                    }
                }
                PrivateKey issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, slot, _issuerKey.getYubicoPin());
                issuerKey = new KeyPair(_issuerKey.getPublicKey(), issuerPrivateKey);
            }
        }

        if ((request.getPrincipal() == null || request.getPrincipal().isEmpty())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "principal required");
        }

        try {
            List<AuthorizedKeyEntry> authorizedKeyEntries = AuthorizedKeyEntry.readAuthorizedKeys(new ByteArrayInputStream(request.getOpensshPublicKey().getBytes(StandardCharsets.UTF_8)), true);
            PublicKey publicKey = authorizedKeyEntries.getFirst().resolvePublicKey(null, PublicKeyEntryResolver.IGNORING);

            OpenSshCertificateBuilder openSshCertificateBuilder = OpenSshCertificateBuilder.userCertificate();
            openSshCertificateBuilder.provider(issuerProvider);
            openSshCertificateBuilder.id(UUID.randomUUID().toString());
            openSshCertificateBuilder.serial(System.currentTimeMillis());
            openSshCertificateBuilder.extensions(Arrays.asList(
                    new OpenSshCertificate.CertificateOption("permit-user-rc"),
                    new OpenSshCertificate.CertificateOption("permit-X11-forwarding"),
                    new OpenSshCertificate.CertificateOption("permit-agent-forwarding"),
                    new OpenSshCertificate.CertificateOption("permit-port-forwarding"),
                    new OpenSshCertificate.CertificateOption("permit-pty")));
            openSshCertificateBuilder.principals(List.of(request.getPrincipal()));
            openSshCertificateBuilder.publicKey(publicKey);
            openSshCertificateBuilder.validAfter(Instant.now());
            if (request.getValidityPeriod() <= 0) {
                openSshCertificateBuilder.validBefore(Instant.now().plus(10, ChronoUnit.MINUTES));
            } else if (request.getValidityPeriod() > 480) {
                openSshCertificateBuilder.validBefore(Instant.now().plus(480, ChronoUnit.MINUTES));
            } else {
                openSshCertificateBuilder.validBefore(Instant.now().plus(request.getValidityPeriod(), ChronoUnit.MINUTES));
            }
            OpenSshCertificate certificate = openSshCertificateBuilder.sign(issuerKey, org.apache.sshd.common.config.keys.KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS);

            SshClientGenerateResponse response = new SshClientGenerateResponse();
            response.setOpensshCertificate(PublicKeyEntry.toString(certificate));
            response.setOpensshConfig("Host " + request.getServer() + "\n" +
                    "  HostName " + request.getServer() + "\n" +
                    "  User " + request.getPrincipal() + "\n" +
                    "  IdentityFile pk\n" +
                    "  CertificateFile pk-cert.pub");
            return response;
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public MtlsClientGenerateResponse mtlsClientGenerate(MtlsClientGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        Date _now = LocalDate.now().toDate();

        Certificate _issuerCertificate = this.certificateRepository.findById(request.getIssuer().getCertificateId()).orElseThrow();
        if (_issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (_issuerCertificate.getType() != CertificateTypeEnum.mTLS_SERVER) ||
                _issuerCertificate.getValidFrom().after(_now) ||
                _issuerCertificate.getValidUntil().before(_now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuer().getCertificateId() + " is not valid");
        }

        X509Certificate issuerCertificate = _issuerCertificate.getCertificate();

        Key issuerKey = this.keyRepository.findById(_issuerCertificate.getKey().getId()).orElseThrow();

        SmartCardConnection connection = null;

        Provider issuerProvider = null;
        PrivateKey issuerPrivateKey = null;
        switch (issuerKey.getType()) {
            case ServerKeyJCE -> {
                issuerProvider = new BouncyCastleProvider();
                issuerPrivateKey = PrivateKeyUtils.convert(issuerKey.getPrivateKey(), request.getIssuer().getKeyPassword());
            }
            case ServerKeyYubico -> {
                YubiKeyDevice device = YubicoProviderUtils.lookupDevice(issuerKey.getYubicoSerial());
                if (device == null) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "device not found");
                }
                connection = device.openConnection(SmartCardConnection.class);
                PivSession session = new PivSession(connection);
                session.authenticate(YubicoProviderUtils.hexStringToByteArray(issuerKey.getYubicoManagementKey()));
                issuerProvider = new PivProvider(session);
                KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider);
                Slot slot = null;
                for (Slot s : Slot.values()) {
                    if (s.getStringAlias().equalsIgnoreCase(issuerKey.getYubicoPivSlot())) {
                        slot = s;
                        break;
                    }
                }
                issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, slot, issuerKey.getYubicoPin());
            }
        }

        try {
            Key certificateKey = this.keyRepository.findById(request.getKeyId()).orElseThrow();
            if (certificateKey.getType() == KeyTypeEnum.ServerKeyYubico) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getKeyId() + " is not support");
            }
            PublicKey publicKey = certificateKey.getPublicKey();

            LocalDate now = LocalDate.now();
            X500Name subject = SubjectUtils.generate(request.getCountry(), request.getOrganization(), request.getOrganizationalUnit(), request.getCommonName(), request.getLocality(), request.getProvince(), request.getEmailAddress());
            X509Certificate leafCertificate = PkiUtils.issueLeafCertificate(issuerProvider, issuerPrivateKey, issuerCertificate, crlApi, ocspApi, x509Api, null, publicKey, subject, now.toDate(), now.plusYears(1).toDate(), System.currentTimeMillis(), null, null, null);
            Certificate certificate = new Certificate();
            certificate.setIssuerCertificate(_issuerCertificate);
            certificate.setCountryCode(request.getCountry());
            certificate.setOrganization(request.getOrganization());
            certificate.setOrganizationalUnit(request.getOrganizationalUnit());
            certificate.setCommonName(request.getCommonName());
            certificate.setLocalityName(request.getLocality());
            certificate.setStateOrProvinceName(request.getProvince());
            certificate.setEmailAddress(request.getEmailAddress());
            certificate.setKey(certificateKey);
            certificate.setCertificate(leafCertificate);
            certificate.setSerial(leafCertificate.getSerialNumber().longValueExact());
            certificate.setCreatedDatetime(new Date());
            certificate.setValidFrom(leafCertificate.getNotBefore());
            certificate.setValidUntil(leafCertificate.getNotAfter());
            certificate.setStatus(CertificateStatusEnum.Good);
            certificate.setType(CertificateTypeEnum.mTLS_CLIENT);
            this.certificateRepository.save(certificate);

            MtlsClientGenerateResponse response = new MtlsClientGenerateResponse();
            response.setCertificateId(certificate.getId());
            response.setKeyPassword(request.getKeyPassword());
            response.setCert(leafCertificate);
            response.setPrivkey(PrivateKeyUtils.convert(certificateKey.getPrivateKey(), request.getKeyPassword()));
            return response;
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }

}
