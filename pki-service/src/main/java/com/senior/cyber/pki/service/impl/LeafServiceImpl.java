package com.senior.cyber.pki.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.ServerGenerateRequest;
import com.senior.cyber.pki.common.dto.ServerGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoPassword;
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
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.jasypt.util.text.AES256TextEncryptor;
import org.joda.time.LocalDate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
public class LeafServiceImpl implements LeafService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Autowired
    protected ObjectMapper objectMapper;

    @Override
    public ServerGenerateResponse serverGenerate(ServerGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        Date _now = LocalDate.now().toDate();

        Certificate _issuerCertificate = this.certificateRepository.findById(request.getIssuer().getCertificateId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "certificate is not found"));
        if (_issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (_issuerCertificate.getType() != CertificateTypeEnum.ISSUING_CA && _issuerCertificate.getType() != CertificateTypeEnum.SUBORDINATE_CA) ||
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
            case BC -> {
                PrivateKey privateKey = PrivateKeyUtils.convert(issuerKey.getPrivateKey(), request.getIssuer().getKeyPassword());
                issuer = new Crypto(Utils.BC, _issuerCertificate.getCertificate(), privateKey);
            }
            case Yubico -> {
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
                case BC -> {
                    PrivateKey privateKey = PrivateKeyUtils.convert(leafKey.getPrivateKey(), request.getKeyPassword());
                    leaf = new Crypto(Utils.BC, leafKey.getPublicKey(), privateKey);
                }
                case Yubico -> {
                    AES256TextEncryptor encryptor = new AES256TextEncryptor();
                    encryptor.setPassword(request.getKeyPassword());
                    YubicoPassword yubico = this.objectMapper.readValue(encryptor.decrypt(leafKey.getPrivateKey()), YubicoPassword.class);
                    PrivateKey privateKey = PivUtils.lookupPrivateKey(providers, connections, sessions, slots, serials, keys, leafKey.getId(), yubico);
                    leaf = new Crypto(providers.get(serials.get(leafKey.getId())), leafKey.getPublicKey(), privateKey);
                }
            }

            LocalDate now = LocalDate.now();
            X500Name subject = SubjectUtils.generate(request.getCountry(), request.getOrganization(), request.getOrganizationalUnit(), request.getCommonName(), request.getLocality(), request.getProvince(), request.getEmailAddress());
            List<Integer> keyUsages = new ArrayList<>();
            keyUsages.add(KeyUsage.digitalSignature);
            switch (leafKey.getKeyFormat()) {
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
            X509Certificate leafCertificate = PkiUtils.issueLeafCertificate(issuer.getProvider(), issuer.getPrivateKey(), issuer.getCertificate(), crlApi, ocspApi, x509Api, null, leaf.getPublicKey(), subject, now.toDate(), now.plusYears(1).toDate(), System.currentTimeMillis(), keyUsages, extendedKeyUsages, sans);
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
            certificate.setType(CertificateTypeEnum.TLS_SERVER);
            this.certificateRepository.save(certificate);

            ServerGenerateResponse response = new ServerGenerateResponse();
            response.setCertificateId(certificate.getId());
            response.setKeyPassword(request.getKeyPassword());
            response.setCert(leafCertificate);
            if (leafKey.getType() == KeyTypeEnum.BC) {
                response.setPrivkey(PrivateKeyUtils.convert(leafKey.getPrivateKey(), request.getKeyPassword()));
            }

            List<X509Certificate> chain = new ArrayList<>();
            chain.add(issuer.getCertificate());

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
                if (cert.getType() == CertificateTypeEnum.SUBORDINATE_CA || cert.getType() == CertificateTypeEnum.ISSUING_CA) {
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
                if (cert.getType() == CertificateTypeEnum.SUBORDINATE_CA || cert.getType() == CertificateTypeEnum.ISSUING_CA) {
                    fullchain.add(cert.getCertificate());
                    temp = cert;
                }
            }
            response.setFullchain(fullchain);
            return response;
        } finally {
            for (SmartCardConnection connection : connections.values()) {
                connection.close();
            }
        }
    }

}
