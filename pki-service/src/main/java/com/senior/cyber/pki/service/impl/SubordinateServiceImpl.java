package com.senior.cyber.pki.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.SubordinateGenerateRequest;
import com.senior.cyber.pki.common.dto.SubordinateGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoPassword;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.common.x509.KeyTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.SubordinateService;
import com.senior.cyber.pki.service.Utils;
import com.senior.cyber.pki.common.util.Crypto;
import com.senior.cyber.pki.common.util.PivUtils;
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
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class SubordinateServiceImpl implements SubordinateService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Autowired
    protected ObjectMapper objectMapper;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public SubordinateGenerateResponse subordinateGenerate(SubordinateGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws IOException, ApduException, ApplicationNotAvailableException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, BadResponseException {
        Map<String, SmartCardConnection> connections = new HashMap<>();
        Map<String, KeyStore> keys = new HashMap<>();
        Map<String, PivProvider> providers = new HashMap<>();
        Map<String, PivSession> sessions = new HashMap<>();
        Map<String, Slot> slots = new HashMap<>();
        Map<String, String> serials = new HashMap<>();

        // issuer
        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuer().getCertificateId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "certificate is not found"));
        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));
        Crypto issuer = null;
        switch (issuerKey.getType()) {
            case BC -> {
                PrivateKey privateKey = PrivateKeyUtils.convert(issuerKey.getPrivateKey(), request.getIssuer().getKeyPassword());
                issuer = new Crypto(Utils.BC, issuerCertificate.getCertificate(), privateKey);
            }
            case Yubico -> {
                AES256TextEncryptor encryptor = new AES256TextEncryptor();
                encryptor.setPassword(request.getIssuer().getKeyPassword());
                YubicoPassword yubico = this.objectMapper.readValue(encryptor.decrypt(issuerKey.getPrivateKey()), YubicoPassword.class);
                PrivateKey privateKey = PivUtils.lookupPrivateKey(providers, connections, sessions, slots, serials, keys, issuerKey.getId(), yubico);
                issuer = new Crypto(providers.get(serials.get(issuerKey.getId())), issuerCertificate.getCertificate(), privateKey);
            }
        }

        Key subordinateKey = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));
        Crypto subordinate = null;
        switch (subordinateKey.getType()) {
            case BC -> {
                PrivateKey privateKey = PrivateKeyUtils.convert(subordinateKey.getPrivateKey(), request.getKeyPassword());
                subordinate = new Crypto(Utils.BC, subordinateKey.getPublicKey(), privateKey);
            }
            case Yubico -> {
                AES256TextEncryptor encryptor = new AES256TextEncryptor();
                encryptor.setPassword(request.getKeyPassword());
                YubicoPassword yubico = this.objectMapper.readValue(encryptor.decrypt(subordinateKey.getPrivateKey()), YubicoPassword.class);
                PrivateKey privateKey = PivUtils.lookupPrivateKey(providers, connections, sessions, slots, serials, keys, subordinateKey.getId(), yubico);
                subordinate = new Crypto(providers.get(serials.get(subordinateKey.getId())), subordinateKey.getPublicKey(), privateKey);
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

            X509Certificate subordinateCertificate = PkiUtils.issueSubordinateCA(issuer.getProvider(), issuer.getPrivateKey(), issuer.getCertificate(), crlApi, ocspApi, x509Api, null, subordinate.getPublicKey(), subject, now.toDate(), now.plusYears(5).toDate(), serial);
            subordinate.setCertificate(subordinateCertificate);
            Certificate _subordinateCertificate = new Certificate();
            _subordinateCertificate.setIssuerCertificate(issuerCertificate);
            _subordinateCertificate.setCountryCode(request.getCountry());
            _subordinateCertificate.setOrganization(request.getOrganization());
            _subordinateCertificate.setOrganizationalUnit(request.getOrganizationalUnit());
            _subordinateCertificate.setCommonName(request.getCommonName());
            _subordinateCertificate.setLocalityName(request.getLocality());
            _subordinateCertificate.setStateOrProvinceName(request.getProvince());
            _subordinateCertificate.setEmailAddress(request.getEmailAddress());
            _subordinateCertificate.setKey(subordinateKey);
            _subordinateCertificate.setCertificate(subordinateCertificate);
            _subordinateCertificate.setSerial(serial);
            _subordinateCertificate.setCreatedDatetime(new Date());
            _subordinateCertificate.setValidFrom(subordinateCertificate.getNotBefore());
            _subordinateCertificate.setValidUntil(subordinateCertificate.getNotAfter());
            _subordinateCertificate.setStatus(CertificateStatusEnum.Good);
            _subordinateCertificate.setType(CertificateTypeEnum.SUBORDINATE_CA);
            this.certificateRepository.save(_subordinateCertificate);

            // crl
            Key crlKey = null;
            {
                KeyPair x509 = KeyUtils.generate(KeyFormatEnum.RSA);
                Key key = new Key();
                key.setStatus(KeyStatusEnum.Good);
                key.setType(KeyTypeEnum.BC);
                key.setKeySize(2048);
                key.setKeyFormat(KeyFormatEnum.RSA);
                key.setPrivateKey(PrivateKeyUtils.convert(x509.getPrivate()));
                key.setPublicKey(x509.getPublic());
                key.setCreatedDatetime(new Date());
                this.keyRepository.save(key);
                crlKey = key;
            }
            X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(subordinate.getProvider(), subordinate.getPrivateKey(), subordinate.getCertificate(), crlKey.getPublicKey(), subject, now.toDate(), now.plusYears(1).toDate(), serial + 1);
            Certificate crl = new Certificate();
            crl.setIssuerCertificate(_subordinateCertificate);
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
                KeyPair x509 = KeyUtils.generate(KeyFormatEnum.RSA);
                Key key = new Key();
                key.setStatus(KeyStatusEnum.Good);
                key.setType(KeyTypeEnum.BC);
                key.setKeySize(2048);
                key.setKeyFormat(KeyFormatEnum.RSA);
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
            X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(subordinate.getProvider(), subordinate.getPrivateKey(), subordinate.getCertificate(), ocspKey.getPublicKey(), ocspSubject, now.toDate(), now.plusYears(1).toDate(), serial + 2);
            Certificate ocsp = new Certificate();
            ocsp.setIssuerCertificate(_subordinateCertificate);
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

            _subordinateCertificate.setCrlCertificate(crl);
            _subordinateCertificate.setOcspCertificate(ocsp);
            this.certificateRepository.save(_subordinateCertificate);

            SubordinateGenerateResponse response = new SubordinateGenerateResponse();
            response.setCertificateId(_subordinateCertificate.getId());
            response.setKeyPassword(request.getKeyPassword());
            response.setCertificate(subordinateCertificate);

            PivSession session = sessions.get(serials.get(subordinateKey.getId()));
            if (session != null) {
                Slot slot = slots.get(serials.get(subordinateKey.getId()));
                session.putCertificate(slot, subordinateCertificate);
            }

            return response;
        } finally {
            for (SmartCardConnection connection : connections.values()) {
                connection.close();
            }
        }
    }
}
