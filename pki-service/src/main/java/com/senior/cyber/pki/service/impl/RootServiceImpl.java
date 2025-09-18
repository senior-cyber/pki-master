package com.senior.cyber.pki.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.util.Crypto;
import com.senior.cyber.pki.common.util.PivUtils;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.common.dto.CertificateStatusEnum;
import com.senior.cyber.pki.common.dto.CertificateTypeEnum;
import com.senior.cyber.pki.common.dto.KeyStatusEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.RootService;
import com.senior.cyber.pki.service.Utils;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.jca.PivProvider;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
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

@Slf4j
@Service
public class RootServiceImpl implements RootService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Autowired
    protected ObjectMapper objectMapper;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public RootGenerateResponse rootGenerate(RootGenerateRequest request) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        log.debug("RootGenerateRequest [{}]", this.objectMapper.writeValueAsString(request));
        Map<String, SmartCardConnection> connections = new HashMap<>();
        Map<String, KeyStore> keys = new HashMap<>();
        Map<String, PivProvider> providers = new HashMap<>();
        Map<String, PivSession> sessions = new HashMap<>();
        Map<String, Slot> slots = new HashMap<>();
        Map<String, String> serials = new HashMap<>();

        // root
        Key rootKey = this.keyRepository.findById(request.getKey().getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));
        Crypto root = null;
        switch (rootKey.getType()) {
            case Yubico -> {
                AES256TextEncryptor encryptor = new AES256TextEncryptor();
                encryptor.setPassword(request.getKey().getKeyPassword());
                YubicoPassword yubico = this.objectMapper.readValue(encryptor.decrypt(rootKey.getPrivateKey()), YubicoPassword.class);
                PrivateKey privateKey = PivUtils.lookupPrivateKey(providers, connections, sessions, slots, serials, keys, rootKey.getId(), yubico);
                root = new Crypto(providers.get(serials.get(rootKey.getId())), rootKey.getPublicKey(), privateKey);
            }
            case BC -> {
                PrivateKey privateKey = PrivateKeyUtils.convert(rootKey.getPrivateKey(), request.getKey().getKeyPassword());
                root = new Crypto(Utils.BC, rootKey.getPublicKey(), privateKey);
            }
        }

        LocalDate now = LocalDate.now();

        try {
            X500Name rootSubject = SubjectUtils.generate(
                    request.getSubject().getCountry(),
                    request.getSubject().getOrganization(),
                    request.getSubject().getOrganizationalUnit(),
                    request.getSubject().getCommonName(),
                    request.getSubject().getLocality(),
                    request.getSubject().getProvince(),
                    request.getSubject().getEmailAddress()
            );

            X509Certificate rootCertificate = PkiUtils.issueRootCa(root.getProvider(), root.getPrivateKey(), root.getPublicKey(), rootSubject, now.toDate(), now.plusYears(10).toDate(), System.currentTimeMillis());
            root.setCertificate(rootCertificate);
            Certificate _rootCertificate = new Certificate();
            _rootCertificate.setCountryCode(request.getSubject().getCountry());
            _rootCertificate.setOrganization(request.getSubject().getOrganization());
            _rootCertificate.setOrganizationalUnit(request.getSubject().getOrganizationalUnit());
            _rootCertificate.setCommonName(request.getSubject().getCommonName());
            _rootCertificate.setLocalityName(request.getSubject().getLocality());
            _rootCertificate.setStateOrProvinceName(request.getSubject().getProvince());
            _rootCertificate.setEmailAddress(request.getSubject().getEmailAddress());
            _rootCertificate.setKey(rootKey);
            _rootCertificate.setCertificate(rootCertificate);
            _rootCertificate.setSerial(rootCertificate.getSerialNumber().longValueExact());
            _rootCertificate.setCreatedDatetime(new Date());
            _rootCertificate.setValidFrom(rootCertificate.getNotBefore());
            _rootCertificate.setValidUntil(rootCertificate.getNotAfter());
            _rootCertificate.setStatus(CertificateStatusEnum.Good);
            _rootCertificate.setType(CertificateTypeEnum.ROOT_CA);
            this.certificateRepository.save(_rootCertificate);

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
            X509Certificate crlCertificate = PkiUtils.issueCrlCertificate(root.getProvider(), root.getPrivateKey(), root.getCertificate(), crlKey.getPublicKey(), rootSubject, now.toDate(), now.plusYears(1).toDate(), _rootCertificate.getSerial() + 1);
            Certificate crl = new Certificate();
            crl.setIssuerCertificate(_rootCertificate);
            crl.setCountryCode(request.getSubject().getCountry());
            crl.setOrganization(request.getSubject().getOrganization());
            crl.setOrganizationalUnit(request.getSubject().getOrganizationalUnit());
            crl.setCommonName(request.getSubject().getCommonName());
            crl.setLocalityName(request.getSubject().getLocality());
            crl.setStateOrProvinceName(request.getSubject().getProvince());
            crl.setEmailAddress(request.getSubject().getEmailAddress());
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
                    request.getSubject().getCountry(),
                    request.getSubject().getOrganization(),
                    request.getSubject().getOrganizationalUnit(),
                    request.getSubject().getCommonName() + " OCSP",
                    request.getSubject().getLocality(),
                    request.getSubject().getProvince(),
                    request.getSubject().getEmailAddress()
            );
            X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(root.getProvider(), root.getPrivateKey(), root.getCertificate(), ocspKey.getPublicKey(), ocspSubject, now.toDate(), now.plusYears(1).toDate(), _rootCertificate.getSerial() + 2);
            Certificate ocsp = new Certificate();
            ocsp.setIssuerCertificate(_rootCertificate);
            ocsp.setCountryCode(request.getSubject().getCountry());
            ocsp.setOrganization(request.getSubject().getOrganization());
            ocsp.setOrganizationalUnit(request.getSubject().getOrganizationalUnit());
            ocsp.setCommonName(request.getSubject().getCommonName() + " OCSP");
            ocsp.setLocalityName(request.getSubject().getLocality());
            ocsp.setStateOrProvinceName(request.getSubject().getProvince());
            ocsp.setEmailAddress(request.getSubject().getEmailAddress());
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

            RootGenerateResponse response = RootGenerateResponse.builder()
                    .keyId(rootKey.getId())
                    .certificateId(_rootCertificate.getId())
                    .keyPassword(request.getKey().getKeyPassword())
                    .certificate(_rootCertificate.getCertificate())
                    .build();

            PivSession session = sessions.get(serials.get(rootKey.getId()));
            if (session != null) {
                Slot slot = slots.get(serials.get(rootKey.getId()));
                session.putCertificate(slot, rootCertificate);
            }
            log.debug("RootGenerateResponse [{}]", this.objectMapper.writeValueAsString(response));
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
    public RootRegisterResponse rootRegister(String crlUrl, String ocspUrl, String x509Url, RootRegisterRequest request) throws CertificateException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, OperatorCreationException {
        log.debug("RootRegisterRequest [{}]", this.objectMapper.writeValueAsString(request));
        Key rootKey = this.keyRepository.findById(request.getKey().getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));

        if (rootKey.getType() == KeyTypeEnum.BC) {
            if (rootKey.getPrivateKey() == null || rootKey.getPrivateKey().isEmpty()) {
                if (!PublicKeyUtils.verifyText(rootKey.getPublicKey(), request.getKey().getKeyPassword() + "." + rootKey.getId())) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
                }
            } else {
                if (PrivateKeyUtils.convert(rootKey.getPrivateKey(), request.getKey().getKeyPassword()) == null) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
                }
            }
        } else if (rootKey.getType() == KeyTypeEnum.Yubico) {
            if (!PublicKeyUtils.verifyText(rootKey.getPublicKey(), request.getKey().getKeyPassword() + "." + rootKey.getId())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        }

        long rootSerial = request.getRootCertificate().getSerialNumber().longValueExact();
        long crlSerial = request.getCrlCertificate().getSerialNumber().longValueExact();
        long ocspSerial = request.getOcspCertificate().getSerialNumber().longValueExact();
        if (rootSerial == ocspSerial || rootSerial == crlSerial) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "root certificate serial number, crl certificate serial number, crl certificate serial number are not allowed to be the same");
        }
        if (this.certificateRepository.existsBySerial(rootSerial)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "root certificate serial number already exists");
        }
        if (this.certificateRepository.existsBySerial(crlSerial)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "crl certificate serial number already exists");
        }
        if (this.certificateRepository.existsBySerial(ocspSerial)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "ocsp certificate serial number already exists");
        }

        Certificate rootCertificate = new Certificate();
        rootCertificate.setCountryCode(SubjectUtils.lookupValue(request.getRootCertificate(), BCStyle.C));
        rootCertificate.setOrganization(SubjectUtils.lookupValue(request.getRootCertificate(), BCStyle.O));
        rootCertificate.setOrganizationalUnit(SubjectUtils.lookupValue(request.getRootCertificate(), BCStyle.OU));
        rootCertificate.setCommonName(SubjectUtils.lookupValue(request.getRootCertificate(), BCStyle.CN));
        rootCertificate.setLocalityName(SubjectUtils.lookupValue(request.getRootCertificate(), BCStyle.L));
        rootCertificate.setStateOrProvinceName(SubjectUtils.lookupValue(request.getRootCertificate(), BCStyle.ST));
        rootCertificate.setEmailAddress(SubjectUtils.lookupValue(request.getRootCertificate(), BCStyle.EmailAddress));
        rootCertificate.setKey(rootKey);
        rootCertificate.setCertificate(request.getRootCertificate());
        rootCertificate.setSerial(rootSerial);
        rootCertificate.setCreatedDatetime(new Date());
        rootCertificate.setValidFrom(request.getRootCertificate().getNotBefore());
        rootCertificate.setValidUntil(request.getRootCertificate().getNotAfter());
        rootCertificate.setStatus(CertificateStatusEnum.Good);
        rootCertificate.setType(CertificateTypeEnum.ROOT_CA);
        this.certificateRepository.save(rootCertificate);

        // crl
        Key crlKey = null;
        {
            Key key = new Key();
            key.setStatus(KeyStatusEnum.Good);
            key.setType(KeyTypeEnum.BC);
            key.setKeySize(request.getCrlKeySize());
            key.setKeyFormat(request.getCrlKeyFormat());
            key.setPrivateKey(PrivateKeyUtils.convert(request.getCrlPrivateKey()));
            key.setPublicKey(request.getCrlCertificate().getPublicKey());
            key.setCreatedDatetime(new Date());
            this.keyRepository.save(key);
            crlKey = key;
        }

        Certificate crlCertificate = new Certificate();
        crlCertificate.setIssuerCertificate(rootCertificate);
        crlCertificate.setCountryCode(SubjectUtils.lookupValue(request.getCrlCertificate(), BCStyle.C));
        crlCertificate.setOrganization(SubjectUtils.lookupValue(request.getCrlCertificate(), BCStyle.O));
        crlCertificate.setOrganizationalUnit(SubjectUtils.lookupValue(request.getCrlCertificate(), BCStyle.OU));
        crlCertificate.setCommonName(SubjectUtils.lookupValue(request.getCrlCertificate(), BCStyle.CN));
        crlCertificate.setLocalityName(SubjectUtils.lookupValue(request.getCrlCertificate(), BCStyle.L));
        crlCertificate.setStateOrProvinceName(SubjectUtils.lookupValue(request.getCrlCertificate(), BCStyle.ST));
        crlCertificate.setEmailAddress(SubjectUtils.lookupValue(request.getCrlCertificate(), BCStyle.EmailAddress));
        crlCertificate.setKey(crlKey);
        crlCertificate.setCertificate(request.getCrlCertificate());
        crlCertificate.setSerial(crlSerial);
        crlCertificate.setCreatedDatetime(new Date());
        crlCertificate.setValidFrom(request.getCrlCertificate().getNotBefore());
        crlCertificate.setValidUntil(request.getCrlCertificate().getNotAfter());
        crlCertificate.setStatus(CertificateStatusEnum.Good);
        crlCertificate.setType(CertificateTypeEnum.CRL);
        this.certificateRepository.save(crlCertificate);

        // ocsp
        Key ocspKey = null;
        {
            Key key = new Key();
            key.setStatus(KeyStatusEnum.Good);
            key.setType(KeyTypeEnum.BC);
            key.setKeySize(request.getOcspKeySize());
            key.setKeyFormat(request.getOcspKeyFormat());
            key.setPrivateKey(PrivateKeyUtils.convert(request.getOcspPrivateKey()));
            key.setPublicKey(request.getOcspCertificate().getPublicKey());
            key.setCreatedDatetime(new Date());
            this.keyRepository.save(key);
            ocspKey = key;
        }

        Certificate ocspCertificate = new Certificate();
        ocspCertificate.setIssuerCertificate(rootCertificate);
        ocspCertificate.setCountryCode(SubjectUtils.lookupValue(request.getOcspCertificate(), BCStyle.C));
        ocspCertificate.setOrganization(SubjectUtils.lookupValue(request.getOcspCertificate(), BCStyle.O));
        ocspCertificate.setOrganizationalUnit(SubjectUtils.lookupValue(request.getOcspCertificate(), BCStyle.OU));
        ocspCertificate.setCommonName(SubjectUtils.lookupValue(request.getOcspCertificate(), BCStyle.CN));
        ocspCertificate.setLocalityName(SubjectUtils.lookupValue(request.getOcspCertificate(), BCStyle.L));
        ocspCertificate.setStateOrProvinceName(SubjectUtils.lookupValue(request.getOcspCertificate(), BCStyle.ST));
        ocspCertificate.setEmailAddress(SubjectUtils.lookupValue(request.getOcspCertificate(), BCStyle.EmailAddress));
        ocspCertificate.setKey(ocspKey);
        ocspCertificate.setCertificate(request.getOcspCertificate());
        ocspCertificate.setSerial(ocspSerial);
        ocspCertificate.setCreatedDatetime(new Date());
        ocspCertificate.setValidFrom(request.getOcspCertificate().getNotBefore());
        ocspCertificate.setValidUntil(request.getOcspCertificate().getNotAfter());
        ocspCertificate.setStatus(CertificateStatusEnum.Good);
        ocspCertificate.setType(CertificateTypeEnum.OCSP);
        this.certificateRepository.save(ocspCertificate);

        rootCertificate.setCrlCertificate(crlCertificate);
        rootCertificate.setOcspCertificate(rootCertificate);
        this.certificateRepository.save(rootCertificate);

        RootRegisterResponse response = RootRegisterResponse.builder()
                .certificateId(rootCertificate.getId())
                .keyId(rootKey.getId())
                .keyPassword(request.getKey().getKeyPassword()).
                certificate(request.getRootCertificate()).build();
        log.debug("RootRegisterResponse [{}]", this.objectMapper.writeValueAsString(response));
        return response;
    }

}
