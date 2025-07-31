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
import com.senior.cyber.pki.service.util.OpenSshCertificateBuilder;
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
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyEncryptionContext;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;
import org.apache.sshd.common.util.io.output.SecureByteArrayOutputStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.joda.time.LocalDate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class CertificateServiceImpl implements CertificateService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public LeafGenerateResponse certificateCommonGenerate(User user, LeafGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        Date now = LocalDate.now().toDate();

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Root && issuerCertificate.getType() != CertificateTypeEnum.Intermediate) ||
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
            LeafGenerateResponse response = null;
            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                PivSession session = new PivSession(connection);
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
    protected LeafGenerateResponse issuingCommonCertificate(Provider issuerProvider, Certificate issuerCertificate, PrivateKey issuerPrivateKey, User user, LeafGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
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
        certificate.setType(CertificateTypeEnum.Leaf);
        certificate.setUser(user);
        this.certificateRepository.save(certificate);

        LeafGenerateResponse response = new LeafGenerateResponse();
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
            if (cert.getType() == CertificateTypeEnum.Intermediate) {
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
            if (cert.getType() == CertificateTypeEnum.Intermediate) {
                fullchain.add(cert.getCertificate());
                temp = cert;
            }
        }
        response.setFullchain(fullchain);

        return response;
    }

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public ServerCertificateGenerateResponse certificateTlsClientGenerate(User user, ServerCertificateGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        Date now = LocalDate.now().toDate();

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Root && issuerCertificate.getType() != CertificateTypeEnum.Intermediate) ||
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
            ServerCertificateGenerateResponse response = null;
            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                PivSession session = new PivSession(connection);
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
    public ServerCertificateGenerateResponse certificateTlsServerGenerate(User user, ServerCertificateGenerateRequest request, String crlApi, String ocspApi, String x509Api, Slot issuerPivSlot) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        Date now = LocalDate.now().toDate();

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Root && issuerCertificate.getType() != CertificateTypeEnum.Intermediate) ||
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
            ServerCertificateGenerateResponse response = null;
            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                PivSession session = new PivSession(connection);
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
    protected ServerCertificateGenerateResponse issuingTlsServerCertificate(Provider issuerProvider, Certificate issuerCertificate, PrivateKey issuerPrivateKey, User user, ServerCertificateGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        if (request.getSans() == null || request.getSans().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "sans are required");
        }

        InetAddressValidator ipValidator = InetAddressValidator.getInstance();
        DomainValidator dnsValidator = DomainValidator.getInstance(true);
        for (String san : request.getSans()) {
            if (!ipValidator.isValid(san) && !dnsValidator.isValid(san)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid " + san);
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

        X509Certificate certificateCertificate = CertificateUtils.generateTlsServer(issuerProvider, issuerCertificate.getCertificate(), issuerPrivateKey, publicKey, subject, crlApi, ocspApi, x509Api, request.getSans(), System.currentTimeMillis());
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
        certificate.setSan(StringUtils.join(request.getSans(), ", "));
        certificate.setCertificate(certificateCertificate);
        certificate.setSerial(certificateCertificate.getSerialNumber().longValueExact());
        certificate.setCreatedDatetime(new Date());
        certificate.setValidFrom(certificateCertificate.getNotBefore());
        certificate.setValidUntil(certificateCertificate.getNotAfter());
        certificate.setStatus(CertificateStatusEnum.Good);
        certificate.setType(CertificateTypeEnum.Leaf);
        certificate.setUser(user);
        this.certificateRepository.save(certificate);

        ServerCertificateGenerateResponse response = new ServerCertificateGenerateResponse();
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
            if (cert.getType() == CertificateTypeEnum.Intermediate) {
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
            if (cert.getType() == CertificateTypeEnum.Intermediate) {
                fullchain.add(cert.getCertificate());
                temp = cert;
            }
        }
        response.setFullchain(fullchain);

        return response;
    }

    @Transactional
    protected ServerCertificateGenerateResponse issuingTlsClientCertificate(Provider issuerProvider, Certificate issuerCertificate, PrivateKey issuerPrivateKey, User user, ServerCertificateGenerateRequest request, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        if (request.getSans() == null || request.getSans().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "sans are required");
        }

        InetAddressValidator ipValidator = InetAddressValidator.getInstance();
        DomainValidator dnsValidator = DomainValidator.getInstance(true);
        for (String san : request.getSans()) {
            if (!ipValidator.isValid(san) && !dnsValidator.isValid(san)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid " + san);
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

        X509Certificate certificateCertificate = CertificateUtils.generateTlsClient(issuerProvider, issuerCertificate.getCertificate(), issuerPrivateKey, publicKey, subject, crlApi, ocspApi, x509Api, request.getSans(), System.currentTimeMillis());
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
        certificate.setSan(StringUtils.join(request.getSans(), ", "));
        certificate.setCertificate(certificateCertificate);
        certificate.setSerial(certificateCertificate.getSerialNumber().longValueExact());
        certificate.setCreatedDatetime(new Date());
        certificate.setValidFrom(certificateCertificate.getNotBefore());
        certificate.setValidUntil(certificateCertificate.getNotAfter());
        certificate.setStatus(CertificateStatusEnum.Good);
        certificate.setType(CertificateTypeEnum.Leaf);
        certificate.setUser(user);
        this.certificateRepository.save(certificate);

        ServerCertificateGenerateResponse response = new ServerCertificateGenerateResponse();
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
            if (cert.getType() == CertificateTypeEnum.Intermediate) {
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
            if (cert.getType() == CertificateTypeEnum.Intermediate) {
                fullchain.add(cert.getCertificate());
                temp = cert;
            }
        }
        response.setFullchain(fullchain);

        return response;
    }

    @Override
    @Transactional
    public SshCertificateGenerateResponse certificateSshGenerate(User user, SshCertificateGenerateRequest request) {
        Date now = LocalDate.now().toDate();

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Root && issuerCertificate.getType() != CertificateTypeEnum.Intermediate) ||
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
            return issuingSshCertificate(issuerProvider, issuerCertificate, issuerPrivateKey, user, request);
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
        }
    }

    @Transactional
    protected SshCertificateGenerateResponse issuingSshCertificate(Provider issuerProvider, Certificate issuerCertificate, PrivateKey issuerPrivateKey, User user, SshCertificateGenerateRequest request) {
        if ((request.getPrincipal() == null || request.getPrincipal().isEmpty())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "principal required");
        }

        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        if (request.getOpensshPublicKey() != null && !request.getOpensshPublicKey().isBlank()) {
            List<AuthorizedKeyEntry> authorizedKeyEntries = null;
            try {
                authorizedKeyEntries = AuthorizedKeyEntry.readAuthorizedKeys(new ByteArrayInputStream(request.getOpensshPublicKey().getBytes(StandardCharsets.UTF_8)), true);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            try {
                publicKey = authorizedKeyEntries.getFirst().resolvePublicKey(null, PublicKeyEntryResolver.IGNORING);
            } catch (IOException | GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        } else {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            publicKey = x509.getPublic();
            privateKey = x509.getPrivate();
        }

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
        OpenSshCertificate certificate = null;
        try {
            certificate = openSshCertificateBuilder.sign(new KeyPair(issuerCertificate.getKey().getPublicKey(), issuerPrivateKey), org.apache.sshd.common.config.keys.KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        SshCertificateGenerateResponse response = new SshCertificateGenerateResponse();
        response.setOpensshCertificate(PublicKeyEntry.toString(certificate));

        if (privateKey != null) {
            try (ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
                OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(new KeyPair(publicKey, privateKey), "", new OpenSSHKeyEncryptionContext(), out);
                response.setOpensshPrivateKey(out.toString(StandardCharsets.UTF_8));
            } catch (IOException | GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        }

        response.setOpensshConfig("Host " + request.getServer() + "\n" +
                "  HostName " + request.getServer() + "\n" +
                "  User " + request.getPrincipal() + "\n" +
                "  IdentityFile pk\n" +
                "  CertificateFile pk-cert.pub");

        return response;
    }

}
