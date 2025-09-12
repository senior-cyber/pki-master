package com.senior.cyber.pki.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.IssuerGenerateRequest;
import com.senior.cyber.pki.common.dto.IssuerGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoPassword;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.IssuerService;
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
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.jasypt.util.text.AES256TextEncryptor;
import org.joda.time.LocalDate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class IssuerServiceImpl implements IssuerService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Autowired
    protected ObjectMapper objectMapper;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public IssuerGenerateResponse issuerGenerate(IssuerGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws IOException, ApduException, ApplicationNotAvailableException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, BadResponseException {
        Provider issuerProvider = null;
        Provider provider = null;
        Map<String, SmartCardConnection> connections = new HashMap<>();
        Map<String, KeyStore> keys = new HashMap<>();
        Map<String, Slot> slots = new HashMap<>();
        Map<String, PivSession> sessions = new HashMap<>();

        // issuer
        Certificate _issuerCertificate = this.certificateRepository.findById(request.getIssuer().getCertificateId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "certificate is not found"));
        Key _issuerKey = this.keyRepository.findById(_issuerCertificate.getKey().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));
        X509Certificate issuerCertificate = _issuerCertificate.getCertificate();
        PrivateKey issuerPrivateKey = null;
        switch (_issuerKey.getType()) {
            case ServerKeyJCE -> {
                issuerProvider = Utils.BC;
                issuerPrivateKey = PrivateKeyUtils.convert(_issuerKey.getPrivateKey(), request.getIssuer().getKeyPassword());
            }
            case ServerKeyYubico -> {
                AES256TextEncryptor encryptor = new AES256TextEncryptor();
                encryptor.setPassword(request.getIssuer().getKeyPassword());
                YubicoPassword yubicoIssuer = this.objectMapper.readValue(encryptor.decrypt(_issuerKey.getPrivateKey()), YubicoPassword.class);

                YubiKeyDevice device = YubicoProviderUtils.lookupDevice(yubicoIssuer.getSerial());
                SmartCardConnection connection = device.openConnection(SmartCardConnection.class);
                connections.put(yubicoIssuer.getSerial(), connection);
                PivSession session = new PivSession(connection);
                session.authenticate(YubicoProviderUtils.hexStringToByteArray(yubicoIssuer.getManagementKey()));
                sessions.put(yubicoIssuer.getSerial(), session);
                issuerProvider = new PivProvider(session);
                KeyStore ks = YubicoProviderUtils.lookupKeyStore(issuerProvider);
                keys.put(yubicoIssuer.getSerial(), ks);
                Slot slot = null;
                for (Slot s : Slot.values()) {
                    if (s.getStringAlias().equalsIgnoreCase(yubicoIssuer.getPivSlot())) {
                        slot = s;
                        break;
                    }
                }
                issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(ks, slot, yubicoIssuer.getPin());
            }
        }

        Key _intermediateKey = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));
        PublicKey publicKey = _intermediateKey.getPublicKey();
        PrivateKey privateKey = null;
        YubicoPassword yubico = null;
        switch (_intermediateKey.getType()) {
            case ServerKeyJCE -> {
                provider = Utils.BC;
                privateKey = PrivateKeyUtils.convert(_intermediateKey.getPrivateKey(), request.getKeyPassword());
            }
            case ServerKeyYubico -> {
                SmartCardConnection connection = null;
                KeyStore ks = null;

                AES256TextEncryptor encryptor = new AES256TextEncryptor();
                encryptor.setPassword(request.getKeyPassword());
                yubico = this.objectMapper.readValue(encryptor.decrypt(_intermediateKey.getPrivateKey()), YubicoPassword.class);

                if (!connections.containsKey(yubico.getSerial())) {
                    YubiKeyDevice device = YubicoProviderUtils.lookupDevice(yubico.getSerial());
                    connection = device.openConnection(SmartCardConnection.class);
                    connections.put(yubico.getSerial(), connection);
                    PivSession session = new PivSession(connection);
                    session.authenticate(YubicoProviderUtils.hexStringToByteArray(yubico.getManagementKey()));
                    sessions.put(yubico.getSerial(), session);
                    provider = new PivProvider(session);
                    ks = YubicoProviderUtils.lookupKeyStore(provider);
                } else {
                    provider = issuerProvider;
                    ks = keys.get(yubico.getSerial());
                }
                Slot slot = null;
                for (Slot s : Slot.values()) {
                    if (s.getStringAlias().equalsIgnoreCase(yubico.getPivSlot())) {
                        slot = s;
                        break;
                    }
                }
                slots.put(yubico.getSerial(), slot);
                privateKey = YubicoProviderUtils.lookupPrivateKey(ks, slot, yubico.getPin());
            }
        }

        try {
            LocalDate now = LocalDate.now();

            X500Name subject = SubjectUtils.generate(
                    request.getCountry(),
                    request.getOrganization(),
                    request.getOrganizationalUnit(),
                    request.getCommonName(),
                    request.getLocality(),
                    request.getProvince(),
                    request.getEmailAddress()
            );
            long serial = System.currentTimeMillis();
            X509Certificate __issuerCertificate = PkiUtils.issueIssuingCa(issuerProvider, issuerPrivateKey, issuerCertificate, crlApi, ocspApi, x509Api, null, publicKey, subject, now.toDate(), now.plusYears(5).toDate(), serial);
            Certificate issuer = new Certificate();
            issuer.setIssuerCertificate(_issuerCertificate);
            issuer.setCountryCode(request.getCountry());
            issuer.setOrganization(request.getOrganization());
            issuer.setOrganizationalUnit(request.getOrganizationalUnit());
            issuer.setCommonName(request.getCommonName());
            issuer.setLocalityName(request.getLocality());
            issuer.setStateOrProvinceName(request.getProvince());
            issuer.setEmailAddress(request.getEmailAddress());
            issuer.setKey(_intermediateKey);
            issuer.setCertificate(__issuerCertificate);
            issuer.setSerial(serial);
            issuer.setCreatedDatetime(new Date());
            issuer.setValidFrom(__issuerCertificate.getNotBefore());
            issuer.setValidUntil(__issuerCertificate.getNotAfter());
            issuer.setStatus(CertificateStatusEnum.Good);
            issuer.setType(CertificateTypeEnum.ISSUING_CA);
            this.certificateRepository.save(issuer);

            // crl
            Key crlKey = null;
            {
                KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
                Key key = new Key();
                key.setStatus(KeyStatusEnum.Good);
                key.setType(KeyTypeEnum.ServerKeyJCE);
                key.setKeySize(2048);
                key.setKeyFormat(KeyFormat.RSA);
                key.setPrivateKey(PrivateKeyUtils.convert(x509.getPrivate()));
                key.setPublicKey(x509.getPublic());
                key.setCreatedDatetime(new Date());
                this.keyRepository.save(key);
                crlKey = key;
            }
            X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(provider, privateKey, __issuerCertificate, crlKey.getPublicKey(), subject, now.toDate(), now.plusYears(1).toDate(), serial + 1);
            Certificate crl = new Certificate();
            crl.setIssuerCertificate(issuer);
            crl.setCountryCode(request.getCountry());
            crl.setOrganization(request.getOrganization());
            crl.setOrganizationalUnit(request.getOrganizationalUnit());
            crl.setCommonName(request.getCommonName());
            crl.setLocalityName(request.getLocality());
            crl.setStateOrProvinceName(request.getProvince());
            crl.setEmailAddress(request.getEmailAddress());
            crl.setKey(crlKey);
            crl.setCertificate(crlCertificate);
            crl.setSerial(crlCertificate.getSerialNumber().longValueExact());
            crl.setCreatedDatetime(new Date());
            crl.setValidFrom(crlCertificate.getNotBefore());
            crl.setValidUntil(crlCertificate.getNotAfter());
            crl.setStatus(CertificateStatusEnum.Good);
            crl.setType(CertificateTypeEnum.CRL);
            this.certificateRepository.save(crl);

            // ocsp
            Key ocspKey = null;
            {
                KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
                Key key = new Key();
                key.setStatus(KeyStatusEnum.Good);
                key.setType(KeyTypeEnum.ServerKeyJCE);
                key.setKeySize(2048);
                key.setKeyFormat(KeyFormat.RSA);
                key.setPrivateKey(PrivateKeyUtils.convert(x509.getPrivate()));
                key.setPublicKey(x509.getPublic());
                key.setCreatedDatetime(new Date());
                this.keyRepository.save(key);
                ocspKey = key;
            }
            X500Name ocspSubject = SubjectUtils.generate(
                    request.getCountry(),
                    request.getOrganization(),
                    request.getOrganizationalUnit(),
                    request.getCommonName() + " OCSP",
                    request.getLocality(),
                    request.getProvince(),
                    request.getEmailAddress()
            );
            X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(provider, privateKey, __issuerCertificate, ocspKey.getPublicKey(), ocspSubject, now.toDate(), now.plusYears(1).toDate(), serial + 2);
            Certificate ocsp = new Certificate();
            ocsp.setIssuerCertificate(issuer);
            ocsp.setCountryCode(request.getCountry());
            ocsp.setOrganization(request.getOrganization());
            ocsp.setOrganizationalUnit(request.getOrganizationalUnit());
            ocsp.setCommonName(request.getCommonName() + " OCSP");
            ocsp.setLocalityName(request.getLocality());
            ocsp.setStateOrProvinceName(request.getProvince());
            ocsp.setEmailAddress(request.getEmailAddress());
            ocsp.setKey(ocspKey);
            ocsp.setCertificate(ocspCertificate);
            ocsp.setSerial(ocspCertificate.getSerialNumber().longValueExact());
            ocsp.setCreatedDatetime(new Date());
            ocsp.setValidFrom(ocspCertificate.getNotBefore());
            ocsp.setValidUntil(ocspCertificate.getNotAfter());
            ocsp.setStatus(CertificateStatusEnum.Good);
            ocsp.setType(CertificateTypeEnum.OCSP);
            this.certificateRepository.save(ocsp);

            issuer.setCrlCertificate(crl);
            issuer.setOcspCertificate(ocsp);
            this.certificateRepository.save(issuer);

            IssuerGenerateResponse response = new IssuerGenerateResponse();
            response.setCertificateId(issuer.getId());
            response.setKeyPassword(request.getKeyPassword());
            response.setCertificate(__issuerCertificate);

            PivSession session = sessions.get(yubico.getSerial());
            if (session != null) {
                session.putCertificate(slots.get(yubico.getSerial()), __issuerCertificate);
            }
            return response;
        } finally {
            for (SmartCardConnection connection : connections.values()) {
                connection.close();
            }
        }
    }
}
