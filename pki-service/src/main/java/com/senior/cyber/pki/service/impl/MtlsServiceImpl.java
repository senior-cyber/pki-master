package com.senior.cyber.pki.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.MtlsService;
import com.senior.cyber.pki.service.Utils;
import com.senior.cyber.pki.service.util.Crypto;
import com.senior.cyber.pki.service.util.PivUtils;
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
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class MtlsServiceImpl implements MtlsService {

    private static final Logger LOGGER = LoggerFactory.getLogger(MtlsServiceImpl.class);

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Autowired
    protected ObjectMapper objectMapper;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public MtlsGenerateResponse mtlsGenerate(MtlsGenerateRequest request) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        Map<String, SmartCardConnection> connections = new HashMap<>();
        Map<String, KeyStore> keys = new HashMap<>();
        Map<String, PivProvider> providers = new HashMap<>();
        Map<String, PivSession> sessions = new HashMap<>();
        Map<String, Slot> slots = new HashMap<>();
        Map<String, String> serials = new HashMap<>();

        // root
        Key rootKey = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));
        Crypto root = null;
        switch (rootKey.getType()) {
            case ServerKeyYubico -> {
                AES256TextEncryptor encryptor = new AES256TextEncryptor();
                encryptor.setPassword(request.getKeyPassword());
                YubicoPassword yubico = this.objectMapper.readValue(encryptor.decrypt(rootKey.getPrivateKey()), YubicoPassword.class);
                PrivateKey privateKey = PivUtils.lookupPrivateKey(providers, connections, sessions, slots, serials, keys, rootKey.getId(), yubico);
                root = new Crypto(providers.get(serials.get(rootKey.getId())), rootKey.getPublicKey(), privateKey);
            }
            case ServerKeyJCE -> {
                PrivateKey privateKey = PrivateKeyUtils.convert(rootKey.getPrivateKey(), request.getKeyPassword());
                root = new Crypto(Utils.BC, rootKey.getPublicKey(), privateKey);
            }
        }

        LocalDate now = LocalDate.now();

        try {
            X500Name rootSubject = SubjectUtils.generate(
                    request.getCountry(),
                    request.getOrganization(),
                    request.getOrganizationalUnit(),
                    request.getCommonName(),
                    request.getLocality(),
                    request.getProvince(),
                    null
            );

            X509Certificate rootCertificate = PkiUtils.issueRootCa(root.getProvider(), root.getPrivateKey(), root.getPublicKey(), rootSubject, now.toDate(), now.plusYears(10).toDate(), System.currentTimeMillis());
            root.setCertificate(rootCertificate);
            Certificate _rootCertificate = new Certificate();
            _rootCertificate.setCountryCode(request.getCountry());
            _rootCertificate.setOrganization(request.getOrganization());
            _rootCertificate.setOrganizationalUnit(request.getOrganizationalUnit());
            _rootCertificate.setCommonName(request.getCommonName());
            _rootCertificate.setLocalityName(request.getLocality());
            _rootCertificate.setStateOrProvinceName(request.getProvince());
            _rootCertificate.setKey(rootKey);
            _rootCertificate.setCertificate(rootCertificate);
            _rootCertificate.setSerial(rootCertificate.getSerialNumber().longValueExact());
            _rootCertificate.setCreatedDatetime(new Date());
            _rootCertificate.setValidFrom(rootCertificate.getNotBefore());
            _rootCertificate.setValidUntil(rootCertificate.getNotAfter());
            _rootCertificate.setStatus(CertificateStatusEnum.Good);
            _rootCertificate.setType(CertificateTypeEnum.mTLS_SERVER);
            this.certificateRepository.save(_rootCertificate);

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
            X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(root.getProvider(), root.getPrivateKey(), root.getCertificate(), crlKey.getPublicKey(), rootSubject, now.toDate(), now.plusYears(1).toDate(), _rootCertificate.getSerial() + 1);
            Certificate crl = new Certificate();
            crl.setIssuerCertificate(_rootCertificate);
            crl.setCountryCode(request.getCountry());
            crl.setOrganization(request.getOrganization());
            crl.setOrganizationalUnit(request.getOrganizationalUnit());
            crl.setCommonName(request.getCommonName());
            crl.setLocalityName(request.getLocality());
            crl.setStateOrProvinceName(request.getProvince());
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
                    null
            );
            X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(root.getProvider(), root.getPrivateKey(), root.getCertificate(), ocspKey.getPublicKey(), ocspSubject, now.toDate(), now.plusYears(1).toDate(), _rootCertificate.getSerial() + 2);
            Certificate ocsp = new Certificate();
            ocsp.setIssuerCertificate(_rootCertificate);
            ocsp.setCountryCode(request.getCountry());
            ocsp.setOrganization(request.getOrganization());
            ocsp.setOrganizationalUnit(request.getOrganizationalUnit());
            ocsp.setCommonName(request.getCommonName() + " OCSP");
            ocsp.setLocalityName(request.getLocality());
            ocsp.setStateOrProvinceName(request.getProvince());
            ocsp.setKey(ocspKey);
            ocsp.setCertificate(ocspCertificate);
            ocsp.setSerial(ocspCertificate.getSerialNumber().longValueExact());
            ocsp.setCreatedDatetime(new Date());
            ocsp.setValidFrom(ocspCertificate.getNotBefore());
            ocsp.setValidUntil(ocspCertificate.getNotAfter());
            ocsp.setStatus(CertificateStatusEnum.Good);
            ocsp.setType(CertificateTypeEnum.OCSP);
            this.certificateRepository.save(ocsp);

            _rootCertificate.setCrlCertificate(crl);
            _rootCertificate.setOcspCertificate(_rootCertificate);
            this.certificateRepository.save(_rootCertificate);

            MtlsGenerateResponse response = new MtlsGenerateResponse();
            response.setCertificateId(_rootCertificate.getId());
            response.setKeyPassword(request.getKeyPassword());
            response.setCertificate(rootCertificate);

            PivSession session = sessions.get(serials.get(rootKey.getId()));
            if (session != null) {
                Slot slot = slots.get(serials.get(rootKey.getId()));
                session.putCertificate(slot, rootCertificate);
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

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public MtlsClientGenerateResponse mtlsClientGenerate(MtlsClientGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        Date _now = LocalDate.now().toDate();

        Certificate _issuerCertificate = this.certificateRepository.findById(request.getIssuer().getCertificateId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "certificate is not found"));
        if (_issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (_issuerCertificate.getType() != CertificateTypeEnum.mTLS_SERVER) ||
                _issuerCertificate.getValidFrom().after(_now) ||
                _issuerCertificate.getValidUntil().before(_now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuer().getCertificateId() + " is not valid");
        }

        Map<String, SmartCardConnection> connections = new HashMap<>();
        Map<String, KeyStore> keys = new HashMap<>();
        Map<String, PivProvider> providers = new HashMap<>();
        Map<String, PivSession> sessions = new HashMap<>();
        Map<String, Slot> slots = new HashMap<>();
        Map<String, String> serials = new HashMap<>();

        Key issuerKey = this.keyRepository.findById(_issuerCertificate.getKey().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));
        Crypto issuer = null;
        switch (issuerKey.getType()) {
            case ServerKeyJCE -> {
                PrivateKey privateKey = PrivateKeyUtils.convert(issuerKey.getPrivateKey(), request.getIssuer().getKeyPassword());
                issuer = new Crypto(Utils.BC, _issuerCertificate.getCertificate(), privateKey);
            }
            case ServerKeyYubico -> {
                AES256TextEncryptor encryptor = new AES256TextEncryptor();
                encryptor.setPassword(request.getIssuer().getKeyPassword());
                YubicoPassword yubico = this.objectMapper.readValue(encryptor.decrypt(issuerKey.getPrivateKey()), YubicoPassword.class);
                PrivateKey privateKey = PivUtils.lookupPrivateKey(providers, connections, sessions, slots, serials, keys, issuerKey.getId(), yubico);
                issuer = new Crypto(providers.get(serials.get(issuerKey.getId())), _issuerCertificate.getCertificate(), privateKey);
            }
        }

        try {
            Key leafKey = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));
            Crypto leaf = null;
            switch (leafKey.getType()) {
                case ServerKeyJCE -> {
                    PrivateKey privateKey = PrivateKeyUtils.convert(leafKey.getPrivateKey(), request.getKeyPassword());
                    leaf = new Crypto(Utils.BC, leafKey.getPublicKey(), privateKey);
                }
                case ServerKeyYubico -> {
                    AES256TextEncryptor encryptor = new AES256TextEncryptor();
                    encryptor.setPassword(request.getKeyPassword());
                    YubicoPassword yubico = this.objectMapper.readValue(encryptor.decrypt(leafKey.getPrivateKey()), YubicoPassword.class);
                    PrivateKey privateKey = PivUtils.lookupPrivateKey(providers, connections, sessions, slots, serials, keys, leafKey.getId(), yubico);
                    leaf = new Crypto(providers.get(serials.get(leafKey.getId())), leafKey.getPublicKey(), privateKey);
                }
            }

            LocalDate now = LocalDate.now();
            X500Name subject = SubjectUtils.generate(request.getCountry(), request.getOrganization(), request.getOrganizationalUnit(), request.getCommonName(), request.getLocality(), request.getProvince(), request.getEmailAddress());
            X509Certificate leafCertificate = PkiUtils.issueLeafCertificate(issuer.getProvider(), issuer.getPrivateKey(), issuer.getCertificate(), crlApi, ocspApi, x509Api, null, leaf.getPublicKey(), subject, now.toDate(), now.plusYears(1).toDate(), System.currentTimeMillis(), null, null, null);
            Certificate certificate = new Certificate();
            certificate.setIssuerCertificate(_issuerCertificate);
            certificate.setCountryCode(request.getCountry());
            certificate.setOrganization(request.getOrganization());
            certificate.setOrganizationalUnit(request.getOrganizationalUnit());
            certificate.setCommonName(request.getCommonName());
            certificate.setLocalityName(request.getLocality());
            certificate.setStateOrProvinceName(request.getProvince());
            certificate.setEmailAddress(request.getEmailAddress());
            certificate.setKey(leafKey);
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
            if (leafKey.getType() == KeyTypeEnum.ServerKeyJCE) {
                response.setPrivkey(PrivateKeyUtils.convert(leafKey.getPrivateKey(), request.getKeyPassword()));
            }
            return response;
        } finally {
            for (SmartCardConnection connection : connections.values()) {
                connection.close();
            }
        }
    }

}
