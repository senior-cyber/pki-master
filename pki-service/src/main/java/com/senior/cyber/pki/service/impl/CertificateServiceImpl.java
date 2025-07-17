package com.senior.cyber.pki.service.impl;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.CertificateService;
import com.senior.cyber.pki.service.util.YubicoProviderUtils;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.jca.PivProvider;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.sshd.certificate.OpenSshCertificateBuilder;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.LocalDate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Service
public class CertificateServiceImpl implements CertificateService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public CertificateCommonGenerateResponse certificateCommonGenerate(User user, CertificateCommonGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot) {
        Date now = LocalDate.now().toDate();

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Root && issuerCertificate.getType() != CertificateTypeEnum.Issuer) ||
                issuerCertificate.getValidFrom().after(now) ||
                issuerCertificate.getValidUntil().before(now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
        }

        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElse(null);
        if (issuerKey == null) {
            throw new IllegalArgumentException("issuerKey not found");
        }

        if (issuerKey.getType() == KeyTypeEnum.ServerKeyJCE) {
            Provider issuerProvider = new BouncyCastleProvider();
            PrivateKey issuerPrivateKey = issuerKey.getPrivateKey();
            return issuingCommonCertificate(issuerProvider, issuerCertificate, issuerPrivateKey, user, request, crlApi, ocspApi, x509Api);
        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            YubiKeyDevice device = YubicoProviderUtils.lookupDevice(request.getIssuerSerialNumber());
            if (device == null) {
                throw new IllegalArgumentException("device not found");
            }
            CertificateCommonGenerateResponse response = null;
            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                try (PivSession session = new PivSession(connection)) {
                    try {
                        session.authenticate(YubicoProviderUtils.hexStringToByteArray(request.getIssuerManagementKey()));
                    } catch (IOException | ApduException | BadResponseException e) {
                        throw new RuntimeException(e);
                    }
                    Provider issuerProvider = new PivProvider(session);
                    KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider);
                    PrivateKey issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, issuerPivSlot, request.getIssuerPin());

                    response = issuingCommonCertificate(issuerProvider, issuerCertificate, issuerPrivateKey, user, request, crlApi, ocspApi, x509Api);
                    return response;
                }
            } catch (Exception e) {
                if (response != null) {
                    return response;
                } else {
                    throw new RuntimeException(e);
                }
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
        }
    }

    @Transactional
    protected CertificateCommonGenerateResponse issuingCommonCertificate(Provider issuerProvider, Certificate issuerCertificate, PrivateKey issuerPrivateKey, User user, CertificateCommonGenerateRequest request, String crlApi, String ocspApi, String x509Api) {
        Key certificateKey = null;
        PublicKey publicKey = null;
        if (request.getCsr() != null) {
            if (!CsrUtils.isValid(request.getCsr())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getCsr() + " is invalid");
            }
            publicKey = CsrUtils.lookupPublicKey(request.getCsr());

            // certificate
            certificateKey = new Key();
            certificateKey.setUser(user);
            certificateKey.setType(KeyTypeEnum.ClientKey);
            certificateKey.setPublicKey(publicKey);
            certificateKey.setCreatedDatetime(new Date());
            this.keyRepository.save(certificateKey);
        } else {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            publicKey = x509.getPublic();

            // certificate
            certificateKey = new Key();
            certificateKey.setUser(user);
            certificateKey.setType(KeyTypeEnum.ServerKeyJCE);
            certificateKey.setPublicKey(x509.getPublic());
            certificateKey.setPrivateKey(x509.getPrivate());
            certificateKey.setCreatedDatetime(new Date());
            this.keyRepository.save(certificateKey);
        }

        X500Name subject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName(),
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );

        X509Certificate certificateCertificate = CertificateUtils.generateCommon(issuerProvider, issuerCertificate.getCertificate(), issuerPrivateKey, publicKey, subject, crlApi, ocspApi, x509Api, System.currentTimeMillis());
        Certificate certificate = new Certificate();
        certificate.setIssuerCertificate(issuerCertificate);
        certificate.setCountryCode(request.getCountry());
        certificate.setOrganization(request.getOrganization());
        certificate.setOrganizationalUnit(request.getOrganizationalUnit());
        certificate.setCommonName(request.getCommonName());
        certificate.setLocalityName(request.getLocality());
        certificate.setStateOrProvinceName(request.getProvince());
        certificate.setEmailAddress(request.getEmailAddress());
        certificate.setKey(certificateKey);
        certificate.setCertificate(certificateCertificate);
        certificate.setSerial(certificateCertificate.getSerialNumber().longValueExact());
        certificate.setCreatedDatetime(new Date());
        certificate.setValidFrom(certificateCertificate.getNotBefore());
        certificate.setValidUntil(certificateCertificate.getNotAfter());
        certificate.setStatus(CertificateStatusEnum.Good);
        certificate.setType(CertificateTypeEnum.Certificate);
        certificate.setUser(user);
        this.certificateRepository.save(certificate);

        CertificateCommonGenerateResponse response = new CertificateCommonGenerateResponse();
        response.setId(certificate.getId());
        response.setCert(certificateCertificate);
        response.setCertBase64(Base64.getEncoder().encodeToString(CertificateUtils.convert(certificateCertificate).getBytes(StandardCharsets.UTF_8)));
        response.setPrivkey(certificateKey.getPrivateKey());
        response.setPrivkeyBase64(Base64.getEncoder().encodeToString(PrivateKeyUtils.convert(certificateKey.getPrivateKey()).getBytes(StandardCharsets.UTF_8)));

        List<X509Certificate> chain = new ArrayList<>();
        chain.add(issuerCertificate.getCertificate());

        Certificate temp = issuerCertificate;
        while (true) {
            String id = temp.getIssuerCertificate().getId();
            Certificate cert = this.certificateRepository.findById(id).orElse(null);
            if (cert == null) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Root) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Issuer) {
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
            if (cert.getType() == CertificateTypeEnum.Root) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Issuer) {
                fullchain.add(cert.getCertificate());
                temp = cert;
            }
        }
        response.setFullchain(fullchain);

        return response;
    }

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public CertificateTlsGenerateResponse certificateTlsClientGenerate(User user, CertificateTlsGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot) {
        Date now = LocalDate.now().toDate();

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Root && issuerCertificate.getType() != CertificateTypeEnum.Issuer) ||
                issuerCertificate.getValidFrom().after(now) ||
                issuerCertificate.getValidUntil().before(now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
        }

        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElse(null);
        if (issuerKey == null) {
            throw new IllegalArgumentException("issuerKey not found");
        }

        if (issuerKey.getType() == KeyTypeEnum.ServerKeyJCE) {
            Provider issuerProvider = new BouncyCastleProvider();
            PrivateKey issuerPrivateKey = issuerKey.getPrivateKey();
            return issuingTlsClientCertificate(issuerProvider, issuerCertificate, issuerPrivateKey, user, request, crlApi, ocspApi, x509Api);
        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            YubiKeyDevice device = YubicoProviderUtils.lookupDevice(request.getIssuerSerialNumber());
            if (device == null) {
                throw new IllegalArgumentException("device not found");
            }
            CertificateTlsGenerateResponse response = null;
            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                try (PivSession session = new PivSession(connection)) {
                    try {
                        session.authenticate(YubicoProviderUtils.hexStringToByteArray(request.getIssuerManagementKey()));
                    } catch (IOException | ApduException | BadResponseException e) {
                        throw new RuntimeException(e);
                    }
                    Provider issuerProvider = new PivProvider(session);
                    KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider);
                    PrivateKey issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, issuerPivSlot, request.getIssuerPin());

                    response = issuingTlsClientCertificate(issuerProvider, issuerCertificate, issuerPrivateKey, user, request, crlApi, ocspApi, x509Api);
                    return response;
                }
            } catch (Exception e) {
                if (response != null) {
                    return response;
                } else {
                    throw new RuntimeException(e);
                }
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
        }
    }

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public CertificateTlsGenerateResponse certificateTlsServerGenerate(User user, CertificateTlsGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot) {
        Date now = LocalDate.now().toDate();

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Root && issuerCertificate.getType() != CertificateTypeEnum.Issuer) ||
                issuerCertificate.getValidFrom().after(now) ||
                issuerCertificate.getValidUntil().before(now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
        }

        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElse(null);
        if (issuerKey == null) {
            throw new IllegalArgumentException("issuerKey not found");
        }

        if (issuerKey.getType() == KeyTypeEnum.ServerKeyJCE) {
            Provider issuerProvider = new BouncyCastleProvider();
            PrivateKey issuerPrivateKey = issuerKey.getPrivateKey();
            return issuingTlsServerCertificate(issuerProvider, issuerCertificate, issuerPrivateKey, user, request, crlApi, ocspApi, x509Api);
        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            YubiKeyDevice device = YubicoProviderUtils.lookupDevice(request.getIssuerSerialNumber());
            if (device == null) {
                throw new IllegalArgumentException("device not found");
            }
            CertificateTlsGenerateResponse response = null;
            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                try (PivSession session = new PivSession(connection)) {
                    try {
                        session.authenticate(YubicoProviderUtils.hexStringToByteArray(request.getIssuerManagementKey()));
                    } catch (IOException | ApduException | BadResponseException e) {
                        throw new RuntimeException(e);
                    }
                    Provider issuerProvider = new PivProvider(session);
                    KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider);
                    PrivateKey issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, issuerPivSlot, request.getIssuerPin());

                    response = issuingTlsServerCertificate(issuerProvider, issuerCertificate, issuerPrivateKey, user, request, crlApi, ocspApi, x509Api);
                    return response;
                }
            } catch (Exception e) {
                if (response != null) {
                    return response;
                } else {
                    throw new RuntimeException(e);
                }
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
        }
    }

    @Transactional
    protected CertificateTlsGenerateResponse issuingTlsServerCertificate(Provider issuerProvider, Certificate issuerCertificate, PrivateKey issuerPrivateKey, User user, CertificateTlsGenerateRequest request, String crlApi, String ocspApi, String x509Api) {
        if ((request.getIp() == null || request.getIp().isEmpty()) && (request.getDns() == null || request.getDns().isEmpty())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "ip or dns are required");
        }

        if (request.getIp() != null) {
            InetAddressValidator validator = InetAddressValidator.getInstance();
            for (String ip : request.getIp()) {
                if (!validator.isValid(ip)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid " + ip);
                }
            }
        }

        if (request.getDns() != null) {
            DomainValidator validator = DomainValidator.getInstance(true);
            for (String dns : request.getDns()) {
                if (dns.startsWith("*.")) {
                    if (!validator.isValid(dns.substring(2))) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid " + dns);
                    }
                } else {
                    if (!validator.isValid(dns)) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid " + dns);
                    }
                }
            }
        }

        Key certificateKey = null;
        PublicKey publicKey = null;
        if (request.getCsr() != null) {
            if (!CsrUtils.isValid(request.getCsr())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "csr is invalid");
            }
            publicKey = CsrUtils.lookupPublicKey(request.getCsr());
            // certificate
            certificateKey = new Key();
            certificateKey.setType(KeyTypeEnum.ClientKey);
            certificateKey.setPublicKey(publicKey);
            certificateKey.setCreatedDatetime(new Date());
            certificateKey.setUser(user);
            this.keyRepository.save(certificateKey);
        } else {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            publicKey = x509.getPublic();

            // certificate
            certificateKey = new Key();
            certificateKey.setType(KeyTypeEnum.ServerKeyJCE);
            certificateKey.setPublicKey(x509.getPublic());
            certificateKey.setPrivateKey(x509.getPrivate());
            certificateKey.setCreatedDatetime(new Date());
            certificateKey.setUser(user);
            this.keyRepository.save(certificateKey);
        }

        X500Name subject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName(),
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );

        List<String> sans = new ArrayList<>();
        if (request.getIp() != null) {
            for (String ip : request.getIp()) {
                if (!sans.contains(ip)) {
                    sans.add(ip);
                }
            }
        }
        if (request.getDns() != null) {
            for (String dns : request.getDns()) {
                if (!sans.contains(dns)) {
                    sans.add(dns);
                }
            }
        }

        X509Certificate certificateCertificate = CertificateUtils.generateTlsServer(issuerProvider, issuerCertificate.getCertificate(), issuerPrivateKey, publicKey, subject, crlApi, ocspApi, x509Api, request.getIp(), request.getDns(), System.currentTimeMillis());
        Certificate certificate = new Certificate();
        certificate.setIssuerCertificate(issuerCertificate);
        certificate.setCountryCode(request.getCountry());
        certificate.setOrganization(request.getOrganization());
        certificate.setOrganizationalUnit(request.getOrganizationalUnit());
        certificate.setCommonName(request.getCommonName());
        certificate.setLocalityName(request.getLocality());
        certificate.setStateOrProvinceName(request.getProvince());
        certificate.setEmailAddress(request.getEmailAddress());
        certificate.setKey(certificateKey);
        certificate.setSan(StringUtils.join(sans, ", "));
        certificate.setCertificate(certificateCertificate);
        certificate.setSerial(certificateCertificate.getSerialNumber().longValueExact());
        certificate.setCreatedDatetime(new Date());
        certificate.setValidFrom(certificateCertificate.getNotBefore());
        certificate.setValidUntil(certificateCertificate.getNotAfter());
        certificate.setStatus(CertificateStatusEnum.Good);
        certificate.setType(CertificateTypeEnum.Certificate);
        certificate.setUser(user);
        this.certificateRepository.save(certificate);

        CertificateTlsGenerateResponse response = new CertificateTlsGenerateResponse();
        response.setId(certificate.getId());
        response.setCert(certificateCertificate);
        response.setCertBase64(Base64.getEncoder().encodeToString(CertificateUtils.convert(certificateCertificate).getBytes(StandardCharsets.UTF_8)));
        response.setPrivkey(certificateKey.getPrivateKey());
        response.setPrivkeyBase64(Base64.getEncoder().encodeToString(PrivateKeyUtils.convert(certificateKey.getPrivateKey()).getBytes(StandardCharsets.UTF_8)));

        List<X509Certificate> chain = new ArrayList<>();
        chain.add(issuerCertificate.getCertificate());

        Certificate temp = issuerCertificate;
        while (true) {
            if (temp.getIssuerCertificate() == null) {
                break;
            }
            String id = temp.getIssuerCertificate().getId();
            Certificate cert = this.certificateRepository.findById(id).orElse(null);
            if (cert == null) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Root) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Issuer) {
                chain.add(cert.getCertificate());
                temp = cert;
            }
        }
        response.setChain(chain);

        List<X509Certificate> fullchain = new ArrayList<>();
        fullchain.add(certificate.getCertificate());
        temp = certificate;
        while (true) {
            if (temp.getIssuerCertificate() == null) {
                break;
            }
            String id = temp.getIssuerCertificate().getId();
            Certificate cert = this.certificateRepository.findById(id).orElse(null);
            if (cert == null) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Root) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Issuer) {
                fullchain.add(cert.getCertificate());
                temp = cert;
            }
        }
        response.setFullchain(fullchain);

        return response;
    }

    @Transactional
    protected CertificateTlsGenerateResponse issuingTlsClientCertificate(Provider issuerProvider, Certificate issuerCertificate, PrivateKey issuerPrivateKey, User user, CertificateTlsGenerateRequest request, String crlApi, String ocspApi, String x509Api) {
        if ((request.getIp() == null || request.getIp().isEmpty()) && (request.getDns() == null || request.getDns().isEmpty())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "ip or dns are required");
        }

        if (request.getIp() != null) {
            InetAddressValidator validator = InetAddressValidator.getInstance();
            for (String ip : request.getIp()) {
                if (!validator.isValid(ip)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid " + ip);
                }
            }
        }

        if (request.getDns() != null) {
            DomainValidator validator = DomainValidator.getInstance(true);
            for (String dns : request.getDns()) {
                if (dns.startsWith("*.")) {
                    if (!validator.isValid(dns.substring(2))) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid " + dns);
                    }
                } else {
                    if (!validator.isValid(dns)) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid " + dns);
                    }
                }
            }
        }

        Key certificateKey = null;
        PublicKey publicKey = null;
        if (request.getCsr() != null) {
            if (!CsrUtils.isValid(request.getCsr())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "csr is invalid");
            }
            publicKey = CsrUtils.lookupPublicKey(request.getCsr());
            // certificate
            certificateKey = new Key();
            certificateKey.setType(KeyTypeEnum.ClientKey);
            certificateKey.setPublicKey(publicKey);
            certificateKey.setCreatedDatetime(new Date());
            certificateKey.setUser(user);
            this.keyRepository.save(certificateKey);
        } else {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            publicKey = x509.getPublic();

            // certificate
            certificateKey = new Key();
            certificateKey.setType(KeyTypeEnum.ServerKeyJCE);
            certificateKey.setPublicKey(x509.getPublic());
            certificateKey.setPrivateKey(x509.getPrivate());
            certificateKey.setCreatedDatetime(new Date());
            certificateKey.setUser(user);
            this.keyRepository.save(certificateKey);
        }

        X500Name subject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName(),
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );

        List<String> sans = new ArrayList<>();
        if (request.getIp() != null) {
            for (String ip : request.getIp()) {
                if (!sans.contains(ip)) {
                    sans.add(ip);
                }
            }
        }
        if (request.getDns() != null) {
            for (String dns : request.getDns()) {
                if (!sans.contains(dns)) {
                    sans.add(dns);
                }
            }
        }

        X509Certificate certificateCertificate = CertificateUtils.generateTlsClient(issuerProvider, issuerCertificate.getCertificate(), issuerPrivateKey, publicKey, subject, crlApi, ocspApi, x509Api, request.getIp(), request.getDns(), System.currentTimeMillis());
        Certificate certificate = new Certificate();
        certificate.setIssuerCertificate(issuerCertificate);
        certificate.setCountryCode(request.getCountry());
        certificate.setOrganization(request.getOrganization());
        certificate.setOrganizationalUnit(request.getOrganizationalUnit());
        certificate.setCommonName(request.getCommonName());
        certificate.setLocalityName(request.getLocality());
        certificate.setStateOrProvinceName(request.getProvince());
        certificate.setEmailAddress(request.getEmailAddress());
        certificate.setKey(certificateKey);
        certificate.setSan(StringUtils.join(sans, ", "));
        certificate.setCertificate(certificateCertificate);
        certificate.setSerial(certificateCertificate.getSerialNumber().longValueExact());
        certificate.setCreatedDatetime(new Date());
        certificate.setValidFrom(certificateCertificate.getNotBefore());
        certificate.setValidUntil(certificateCertificate.getNotAfter());
        certificate.setStatus(CertificateStatusEnum.Good);
        certificate.setType(CertificateTypeEnum.Certificate);
        certificate.setUser(user);
        this.certificateRepository.save(certificate);

        CertificateTlsGenerateResponse response = new CertificateTlsGenerateResponse();
        response.setId(certificate.getId());
        response.setCert(certificateCertificate);
        response.setCertBase64(Base64.getEncoder().encodeToString(CertificateUtils.convert(certificateCertificate).getBytes(StandardCharsets.UTF_8)));
        response.setPrivkey(certificateKey.getPrivateKey());
        response.setPrivkeyBase64(Base64.getEncoder().encodeToString(PrivateKeyUtils.convert(certificateKey.getPrivateKey()).getBytes(StandardCharsets.UTF_8)));

        List<X509Certificate> chain = new ArrayList<>();
        chain.add(issuerCertificate.getCertificate());

        Certificate temp = issuerCertificate;
        while (true) {
            if (temp.getIssuerCertificate() == null) {
                break;
            }
            String id = temp.getIssuerCertificate().getId();
            Certificate cert = this.certificateRepository.findById(id).orElse(null);
            if (cert == null) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Root) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Issuer) {
                chain.add(cert.getCertificate());
                temp = cert;
            }
        }
        response.setChain(chain);

        List<X509Certificate> fullchain = new ArrayList<>();
        fullchain.add(certificate.getCertificate());
        temp = certificate;
        while (true) {
            if (temp.getIssuerCertificate() == null) {
                break;
            }
            String id = temp.getIssuerCertificate().getId();
            Certificate cert = this.certificateRepository.findById(id).orElse(null);
            if (cert == null) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Root) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Issuer) {
                fullchain.add(cert.getCertificate());
                temp = cert;
            }
        }
        response.setFullchain(fullchain);

        return response;
    }

    @Override
    public CertificateSshGenerateResponse certificateSshGenerate(User user, CertificateSshGenerateRequest request, Slot issuerPivSlot) {
//        // generate public key if not present
//        // convert into java pem
//        // load public key
//
//        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
//        if (issuerCertificate == null) {
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
//        }
//        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
//                (issuerCertificate.getType() != CertificateTypeEnum.Root && issuerCertificate.getType() != CertificateTypeEnum.Issuer) ||
//                issuerCertificate.getValidFrom().after(now) ||
//                issuerCertificate.getValidUntil().before(now)
//        ) {
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
//        }
//
//        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElse(null);
//        if (issuerKey == null) {
//            throw new IllegalArgumentException("issuerKey not found");
//        }
//
//        if (issuerKey.getType() == KeyTypeEnum.ServerKeyJCE) {
//            Provider issuerProvider = new BouncyCastleProvider();
//            PrivateKey issuerPrivateKey = issuerKey.getPrivateKey();
//            return issuingTlsServerCertificate(issuerProvider, issuerCertificate, issuerPrivateKey, user, request, crlApi, ocspApi, x509Api);
//        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
//            YubiKeyDevice device = YubicoProviderUtils.lookupDevice(request.getIssuerSerialNumber());
//            if (device == null) {
//                throw new IllegalArgumentException("device not found");
//            }
//            CertificateTlsGenerateResponse response = null;
//            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
//                try (PivSession session = new PivSession(connection)) {
//                    try {
//                        session.authenticate(YubicoProviderUtils.hexStringToByteArray(request.getIssuerManagementKey()));
//                    } catch (IOException | ApduException | BadResponseException e) {
//                        throw new RuntimeException(e);
//                    }
//                    Provider issuerProvider = new PivProvider(session);
//                    KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider);
//                    PrivateKey issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, issuerPivSlot, request.getIssuerPin());
//
//                    response = issuingTlsServerCertificate(issuerProvider, issuerCertificate, issuerPrivateKey, user, request, crlApi, ocspApi, x509Api);
//                    return response;
//                }
//            } catch (Exception e) {
//                if (response != null) {
//                    return response;
//                } else {
//                    throw new RuntimeException(e);
//                }
//            }
//        } else {
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
//        }
        return null;
    }

    public void pp() throws Exception {

//        PublicKey publicKey = null;
//        KeyPair caKeypair = null;

        KeyPairGenerator userKpg = KeyPairGenerator.getInstance("RSA");
        userKpg.initialize(2048);
        KeyPair userKeyPair = userKpg.generateKeyPair();

        // Generate CA key pair (certificate authority)
        KeyPairGenerator caKpg = KeyPairGenerator.getInstance("RSA");
        caKpg.initialize(2048);
        KeyPair caKeyPair = caKpg.generateKeyPair();

        PublicKey publicKey = caKeyPair.getPublic();

        OpenSshCertificateBuilder openSshCertificateBuilder = OpenSshCertificateBuilder.userCertificate();
//        openSshCertificateBuilder.criticalOptions()
//        openSshCertificateBuilder.extensions()
        openSshCertificateBuilder.id("test-id");
        openSshCertificateBuilder.serial(System.currentTimeMillis());
        // openSshCertificateBuilder.nonce()
        openSshCertificateBuilder.principals(List.of("socheat"));
        openSshCertificateBuilder.publicKey(publicKey);
        openSshCertificateBuilder.validAfter(Instant.now());
        openSshCertificateBuilder.validBefore(Instant.now());
        OpenSshCertificate cert = openSshCertificateBuilder.sign(caKeyPair, "SHA256withRSA");


        String certType = cert.getKeyType(); // e.g., ssh-rsa-cert-v01@openssh.com
        byte[] encoded = cert.getEncoded(); // binary format
        String base64 = Base64.getEncoder().encodeToString(encoded);

        // Write to file: <type> <base64> <comment>
        String comment = "user@example.com-cert";
        String line = certType + " " + base64 + " " + comment + "\n";

        Path output = Path.of("id_rsa-cert.pub");
        Files.writeString(output, line);

        System.out.println("Written OpenSSH certificate to: " + output.toAbsolutePath());


//        X509Certificate certificateCertificate = CertificateUtils.generateTlsClient(issuerProvider, issuerCertificate.getCertificate(), issuerPrivateKey, publicKey, subject, crlApi, ocspApi, x509Api, request.getIp(), request.getDns(), System.currentTimeMillis());
//        Certificate certificate = new Certificate();
//        certificate.setIssuerCertificate(issuerCertificate);
//        certificate.setCountryCode(request.getCountry());
//        certificate.setOrganization(request.getOrganization());
//        certificate.setOrganizationalUnit(request.getOrganizationalUnit());
//        certificate.setCommonName(request.getCommonName());
//        certificate.setLocalityName(request.getLocality());
//        certificate.setStateOrProvinceName(request.getProvince());
//        certificate.setEmailAddress(request.getEmailAddress());
//        certificate.setKey(certificateKey);
//        certificate.setSan(StringUtils.join(sans, ", "));
//        certificate.setCertificate(certificateCertificate);
//        certificate.setSerial(certificateCertificate.getSerialNumber().longValueExact());
//        certificate.setCreatedDatetime(new Date());
//        certificate.setValidFrom(certificateCertificate.getNotBefore());
//        certificate.setValidUntil(certificateCertificate.getNotAfter());
//        certificate.setStatus(CertificateStatusEnum.Good);
//        certificate.setType(CertificateTypeEnum.Certificate);
//        certificate.setUser(user);
//        this.certificateRepository.save(certificate);
//
//        CertificateSshGenerateResponse response = new CertificateSshGenerateResponse();
//
//
//        return response;
    }

    @Transactional
    protected CertificateTlsGenerateResponse issuingSshCertificate(Provider issuerProvider, Certificate issuerCertificate, PrivateKey issuerPrivateKey, User user, CertificateTlsGenerateRequest request, String crlApi, String ocspApi, String x509Api) {
        // TODO:
        if ((request.getIp() == null || request.getIp().isEmpty()) && (request.getDns() == null || request.getDns().isEmpty())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "ip or dns are required");
        }

        if (request.getIp() != null) {
            InetAddressValidator validator = InetAddressValidator.getInstance();
            for (String ip : request.getIp()) {
                if (!validator.isValid(ip)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid " + ip);
                }
            }
        }

        if (request.getDns() != null) {
            DomainValidator validator = DomainValidator.getInstance(true);
            for (String dns : request.getDns()) {
                if (dns.startsWith("*.")) {
                    if (!validator.isValid(dns.substring(2))) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid " + dns);
                    }
                } else {
                    if (!validator.isValid(dns)) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid " + dns);
                    }
                }
            }
        }

        Key certificateKey = null;
        PublicKey publicKey = null;
        if (request.getCsr() != null) {
            if (!CsrUtils.isValid(request.getCsr())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "csr is invalid");
            }
            publicKey = CsrUtils.lookupPublicKey(request.getCsr());
            // certificate
            certificateKey = new Key();
            certificateKey.setType(KeyTypeEnum.ClientKey);
            certificateKey.setPublicKey(publicKey);
            certificateKey.setCreatedDatetime(new Date());
            certificateKey.setUser(user);
            this.keyRepository.save(certificateKey);
        } else {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            publicKey = x509.getPublic();

            // certificate
            certificateKey = new Key();
            certificateKey.setType(KeyTypeEnum.ServerKeyJCE);
            certificateKey.setPublicKey(x509.getPublic());
            certificateKey.setPrivateKey(x509.getPrivate());
            certificateKey.setCreatedDatetime(new Date());
            certificateKey.setUser(user);
            this.keyRepository.save(certificateKey);
        }

        X500Name subject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName(),
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );

        List<String> sans = new ArrayList<>();
        if (request.getIp() != null) {
            for (String ip : request.getIp()) {
                if (!sans.contains(ip)) {
                    sans.add(ip);
                }
            }
        }
        if (request.getDns() != null) {
            for (String dns : request.getDns()) {
                if (!sans.contains(dns)) {
                    sans.add(dns);
                }
            }
        }

        X509Certificate certificateCertificate = CertificateUtils.generateTlsServer(issuerProvider, issuerCertificate.getCertificate(), issuerPrivateKey, publicKey, subject, crlApi, ocspApi, x509Api, request.getIp(), request.getDns(), System.currentTimeMillis());
        Certificate certificate = new Certificate();
        certificate.setIssuerCertificate(issuerCertificate);
        certificate.setCountryCode(request.getCountry());
        certificate.setOrganization(request.getOrganization());
        certificate.setOrganizationalUnit(request.getOrganizationalUnit());
        certificate.setCommonName(request.getCommonName());
        certificate.setLocalityName(request.getLocality());
        certificate.setStateOrProvinceName(request.getProvince());
        certificate.setEmailAddress(request.getEmailAddress());
        certificate.setKey(certificateKey);
        certificate.setSan(StringUtils.join(sans, ", "));
        certificate.setCertificate(certificateCertificate);
        certificate.setSerial(certificateCertificate.getSerialNumber().longValueExact());
        certificate.setCreatedDatetime(new Date());
        certificate.setValidFrom(certificateCertificate.getNotBefore());
        certificate.setValidUntil(certificateCertificate.getNotAfter());
        certificate.setStatus(CertificateStatusEnum.Good);
        certificate.setType(CertificateTypeEnum.Certificate);
        certificate.setUser(user);
        this.certificateRepository.save(certificate);

        CertificateTlsGenerateResponse response = new CertificateTlsGenerateResponse();
        response.setId(certificate.getId());
        response.setCert(certificateCertificate);
        response.setCertBase64(Base64.getEncoder().encodeToString(CertificateUtils.convert(certificateCertificate).getBytes(StandardCharsets.UTF_8)));
        response.setPrivkey(certificateKey.getPrivateKey());
        response.setPrivkeyBase64(Base64.getEncoder().encodeToString(PrivateKeyUtils.convert(certificateKey.getPrivateKey()).getBytes(StandardCharsets.UTF_8)));

        List<X509Certificate> chain = new ArrayList<>();
        chain.add(issuerCertificate.getCertificate());

        Certificate temp = issuerCertificate;
        while (true) {
            if (temp.getIssuerCertificate() == null) {
                break;
            }
            String id = temp.getIssuerCertificate().getId();
            Certificate cert = this.certificateRepository.findById(id).orElse(null);
            if (cert == null) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Root) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Issuer) {
                chain.add(cert.getCertificate());
                temp = cert;
            }
        }
        response.setChain(chain);

        List<X509Certificate> fullchain = new ArrayList<>();
        fullchain.add(certificate.getCertificate());
        temp = certificate;
        while (true) {
            if (temp.getIssuerCertificate() == null) {
                break;
            }
            String id = temp.getIssuerCertificate().getId();
            Certificate cert = this.certificateRepository.findById(id).orElse(null);
            if (cert == null) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Root) {
                break;
            }
            if (cert.getType() == CertificateTypeEnum.Issuer) {
                fullchain.add(cert.getCertificate());
                temp = cert;
            }
        }
        response.setFullchain(fullchain);

        return response;
    }
}
