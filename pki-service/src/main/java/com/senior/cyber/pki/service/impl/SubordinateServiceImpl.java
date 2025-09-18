package com.senior.cyber.pki.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.util.Crypto;
import com.senior.cyber.pki.common.util.PivUtils;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.SubordinateService;
import com.senior.cyber.pki.service.Utils;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.jca.PivProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.OperatorCreationException;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
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

        // TODO:
        //  if BC
        //     if decentralized key then put into queue, send email to certificate owner
        //     else server sign
        //  if Yubico
        //     if connected
        //        if server sign
        //        if client sign
        //     else
        //        into queue, send email to certificate owner

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
                    request.getSubject().getCountry(),
                    request.getSubject().getOrganization(),
                    request.getSubject().getOrganizationalUnit(),
                    request.getSubject().getCommonName(),
                    request.getSubject().getLocality(),
                    request.getSubject().getProvince(),
                    request.getSubject().getEmailAddress()
            );
            long serial = System.currentTimeMillis();

            X509Certificate subordinateCertificate = PkiUtils.issueSubordinateCA(issuer.getProvider(), issuer.getPrivateKey(), issuer.getCertificate(), crlApi, ocspApi, x509Api, null, subordinate.getPublicKey(), subject, now.toDate(), now.plusYears(5).toDate(), serial);
            subordinate.setCertificate(subordinateCertificate);
            Certificate _subordinateCertificate = new Certificate();
            _subordinateCertificate.setIssuerCertificate(issuerCertificate);
            _subordinateCertificate.setCountryCode(request.getSubject().getCountry());
            _subordinateCertificate.setOrganization(request.getSubject().getOrganization());
            _subordinateCertificate.setOrganizationalUnit(request.getSubject().getOrganizationalUnit());
            _subordinateCertificate.setCommonName(request.getSubject().getCommonName());
            _subordinateCertificate.setLocalityName(request.getSubject().getLocality());
            _subordinateCertificate.setStateOrProvinceName(request.getSubject().getProvince());
            _subordinateCertificate.setEmailAddress(request.getSubject().getEmailAddress());
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
            X509Certificate ocspCertificate = PkiUtils.issueOcspCertificate(subordinate.getProvider(), subordinate.getPrivateKey(), subordinate.getCertificate(), ocspKey.getPublicKey(), ocspSubject, now.toDate(), now.plusYears(1).toDate(), serial + 2);
            Certificate ocsp = new Certificate();
            ocsp.setIssuerCertificate(_subordinateCertificate);
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

            _subordinateCertificate.setCrlCertificate(crl);
            _subordinateCertificate.setOcspCertificate(ocsp);
            this.certificateRepository.save(_subordinateCertificate);

            SubordinateGenerateResponse response = SubordinateGenerateResponse.builder()
                    .certificateId(_subordinateCertificate.getId())
                    .keyPassword(request.getKeyPassword())
                    .certificate(subordinateCertificate).build();

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

    @Override
    public SubordinateRegisterResponse subordinateRegister(SubordinateRegisterRequest request, String crlApi, String ocspApi, String x509Api) throws IOException, ApduException, ApplicationNotAvailableException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, BadResponseException, SignatureException, InvalidKeyException {
        Key subordinateKey = this.keyRepository.findById(request.getKey().getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));

        if (subordinateKey.getType() == KeyTypeEnum.BC) {
            if (subordinateKey.getPrivateKey() == null || subordinateKey.getPrivateKey().isEmpty()) {
                if (!PublicKeyUtils.verifyText(subordinateKey.getPublicKey(), request.getKey().getKeyPassword() + "." + subordinateKey.getId())) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
                }
            } else {
                if (PrivateKeyUtils.convert(subordinateKey.getPrivateKey(), request.getKey().getKeyPassword()) == null) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
                }
            }
        } else if (subordinateKey.getType() == KeyTypeEnum.Yubico) {
            AES256TextEncryptor encryptor = new AES256TextEncryptor();
            encryptor.setPassword(request.getKey().getKeyPassword());
            try {
                encryptor.decrypt(subordinateKey.getPrivateKey());
            } catch (EncryptionOperationNotPossibleException | EncryptionInitializationException e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        }

        long subordinateSerial = request.getSubordinateCertificate().getSerialNumber().longValueExact();
        long crlSerial = request.getCrlCertificate().getSerialNumber().longValueExact();
        long ocspSerial = request.getOcspCertificate().getSerialNumber().longValueExact();
        if (subordinateSerial == ocspSerial || subordinateSerial == crlSerial) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "subordinate certificate serial number, crl certificate serial number, crl certificate serial number are not allowed to be the same");
        }
        if (this.certificateRepository.existsBySerial(subordinateSerial)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "subordinate certificate serial number already exists");
        }
        if (this.certificateRepository.existsBySerial(crlSerial)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "crl certificate serial number already exists");
        }
        if (this.certificateRepository.existsBySerial(ocspSerial)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "ocsp certificate serial number already exists");
        }

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuer().getCertificateId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "certificate is not found"));
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "issuer certificate was revoked");
        }
        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "key is not found"));
        if (issuerKey.getStatus() == KeyStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "issuer certificate was revoked");
        }

        Certificate subordinateCertificate = new Certificate();
        subordinateCertificate.setIssuerCertificate(issuerCertificate);
        subordinateCertificate.setCountryCode(SubjectUtils.lookupValue(request.getSubordinateCertificate(), BCStyle.C));
        subordinateCertificate.setOrganization(SubjectUtils.lookupValue(request.getSubordinateCertificate(), BCStyle.O));
        subordinateCertificate.setOrganizationalUnit(SubjectUtils.lookupValue(request.getSubordinateCertificate(), BCStyle.OU));
        subordinateCertificate.setCommonName(SubjectUtils.lookupValue(request.getSubordinateCertificate(), BCStyle.CN));
        subordinateCertificate.setLocalityName(SubjectUtils.lookupValue(request.getSubordinateCertificate(), BCStyle.L));
        subordinateCertificate.setStateOrProvinceName(SubjectUtils.lookupValue(request.getSubordinateCertificate(), BCStyle.ST));
        subordinateCertificate.setEmailAddress(SubjectUtils.lookupValue(request.getSubordinateCertificate(), BCStyle.EmailAddress));
        subordinateCertificate.setKey(subordinateKey);
        subordinateCertificate.setCertificate(request.getSubordinateCertificate());
        subordinateCertificate.setSerial(subordinateSerial);
        subordinateCertificate.setCreatedDatetime(new Date());
        subordinateCertificate.setValidFrom(request.getSubordinateCertificate().getNotBefore());
        subordinateCertificate.setValidUntil(request.getSubordinateCertificate().getNotAfter());
        subordinateCertificate.setStatus(CertificateStatusEnum.Good);
        subordinateCertificate.setType(CertificateTypeEnum.SUBORDINATE_CA);
        this.certificateRepository.save(subordinateCertificate);

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
        crlCertificate.setIssuerCertificate(subordinateCertificate);
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
        ocspCertificate.setIssuerCertificate(subordinateCertificate);
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

        subordinateCertificate.setCrlCertificate(crlCertificate);
        subordinateCertificate.setOcspCertificate(subordinateCertificate);
        this.certificateRepository.save(subordinateCertificate);

        return SubordinateRegisterResponse.builder()
                .certificateId(subordinateCertificate.getId())
                .keyId(subordinateKey.getId())
                .keyPassword(request.getKey().getKeyPassword())
                .certificate(request.getSubordinateCertificate()).build();
    }

}
