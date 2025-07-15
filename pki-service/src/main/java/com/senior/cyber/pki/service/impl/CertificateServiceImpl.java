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
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.LocalDate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
public class CertificateServiceImpl implements CertificateService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public CertificateCommonCsrResponse certificateCommonGenerate(User user, CertificateCommonCsrRequest request, String crlApi, String ocspApi, String x509Api, YubicoPivSlotEnum issuerPivSlot) {
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
        PrivateKey issuerPrivateKey = null;
        if (issuerKey.getType() == KeyTypeEnum.ServerKeyJCE) {
            issuerPrivateKey = issuerKey.getPrivateKey();
        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            Provider issuerProvider = YubicoProviderUtils.lookProvider(request.getIssuerUsbSlot());
            KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider, request.getIssuerPin());
            issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, issuerPivSlot, null);
        }

        Provider provider = new BouncyCastleProvider();

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        converter.setProvider(provider);

        Key certificateKey = new Key();
        certificateKey.setType(KeyTypeEnum.ServerKeyJCE);
        try {
            certificateKey.setPublicKey(converter.getPublicKey(request.getCsr().getSubjectPublicKeyInfo()));
        } catch (PEMException e) {
            throw new RuntimeException(e);
        }
        certificateKey.setUser(user);
        certificateKey.setCreatedDatetime(new Date());
        this.keyRepository.save(certificateKey);

        Map<ASN1ObjectIdentifier, String> subject = CsrUtils.parse(request.getCsr());

        X509Certificate certificateCertificate = CertificateUtils.generateCommon(issuerCertificate.getCertificate(), issuerPrivateKey, request.getCsr(), crlApi, ocspApi, x509Api, System.currentTimeMillis());
        Certificate certificate = new Certificate();
        certificate.setIssuerCertificate(issuerCertificate);
        certificate.setCountryCode(subject.get(BCStyle.C));
        certificate.setOrganization(subject.get(BCStyle.O));
        certificate.setOrganizationalUnit(subject.get(BCStyle.OU));
        certificate.setCommonName(subject.get(BCStyle.CN));
        certificate.setLocalityName(subject.get(BCStyle.L));
        certificate.setStateOrProvinceName(subject.get(BCStyle.ST));
        certificate.setEmailAddress(subject.get(BCStyle.EmailAddress));
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

        CertificateCommonCsrResponse response = new CertificateCommonCsrResponse();
        response.setSerial(certificate.getSerial());
        return response;
    }

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public CertificateTlsCsrResponse certificateTlsGenerate(User user, CertificateTlsCsrRequest request, String crlApi, String ocspApi, String x509Api, YubicoPivSlotEnum issuerPivSlot) {
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
        PrivateKey issuerPrivateKey = null;
        if (issuerKey.getType() == KeyTypeEnum.ServerKeyJCE) {
            issuerPrivateKey = issuerKey.getPrivateKey();
        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            Provider issuerProvider = YubicoProviderUtils.lookProvider(request.getIssuerUsbSlot());
            KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider, request.getIssuerPin());
            issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, issuerPivSlot, null);
        }

        Provider provider = new BouncyCastleProvider();

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        converter.setProvider(provider);

        Key certificateKey = new Key();
        certificateKey.setType(KeyTypeEnum.ServerKeyJCE);
        try {
            certificateKey.setPublicKey(converter.getPublicKey(request.getCsr().getSubjectPublicKeyInfo()));
        } catch (PEMException e) {
            throw new RuntimeException(e);
        }
        certificateKey.setCreatedDatetime(new Date());
        certificateKey.setUser(user);
        this.keyRepository.save(certificateKey);

        Map<ASN1ObjectIdentifier, String> subject = CsrUtils.parse(request.getCsr());

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

        X509Certificate certificateCertificate = CertificateUtils.generateTls(issuerCertificate.getCertificate(), issuerPrivateKey, request.getCsr(), crlApi, ocspApi, x509Api, request.getIp(), request.getDns(), System.currentTimeMillis());
        Certificate certificate = new Certificate();
        certificate.setIssuerCertificate(issuerCertificate);
        certificate.setCountryCode(subject.get(BCStyle.C));
        certificate.setOrganization(subject.get(BCStyle.O));
        certificate.setOrganizationalUnit(subject.get(BCStyle.OU));
        certificate.setCommonName(subject.get(BCStyle.CN));
        certificate.setLocalityName(subject.get(BCStyle.L));
        certificate.setStateOrProvinceName(subject.get(BCStyle.ST));
        certificate.setEmailAddress(subject.get(BCStyle.EmailAddress));
        certificate.setKey(certificateKey);
        certificate.setCertificate(certificateCertificate);
        certificate.setSan(StringUtils.join(sans, ", "));
        certificate.setSerial(certificateCertificate.getSerialNumber().longValueExact());
        certificate.setCreatedDatetime(new Date());
        certificate.setValidFrom(certificateCertificate.getNotBefore());
        certificate.setValidUntil(certificateCertificate.getNotAfter());
        certificate.setStatus(CertificateStatusEnum.Good);
        certificate.setType(CertificateTypeEnum.Certificate);
        certificate.setUser(user);
        this.certificateRepository.save(certificate);

        CertificateTlsCsrResponse response = new CertificateTlsCsrResponse();
        response.setSerial(certificate.getSerial());
        return response;
    }

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public CertificateCommonGenerateResponse certificateCommonGenerate(User user, CertificateCommonGenerateRequest request, String crlApi, String ocspApi, String x509Api, YubicoPivSlotEnum issuerPivSlot) {
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
        PrivateKey issuerPrivateKey = null;
        if (issuerKey.getType() == KeyTypeEnum.ServerKeyJCE) {
            issuerPrivateKey = issuerKey.getPrivateKey();
        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            Provider issuerProvider = YubicoProviderUtils.lookProvider(request.getIssuerUsbSlot());
            KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider, request.getIssuerPin());
            issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, issuerPivSlot, null);
        }

        KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);

        // certificate
        Key certificateKey = new Key();
        certificateKey.setUser(user);
        certificateKey.setType(KeyTypeEnum.ServerKeyJCE);
        certificateKey.setPublicKey(x509.getPublic());
        certificateKey.setPrivateKey(x509.getPrivate());
        certificateKey.setCreatedDatetime(new Date());
        this.keyRepository.save(certificateKey);

        X500Name certificateSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName(),
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        PKCS10CertificationRequest certificateCsr = CsrUtils.generate(new KeyPair(certificateKey.getPublicKey(), certificateKey.getPrivateKey()), certificateSubject);
        X509Certificate certificateCertificate = CertificateUtils.generateCommon(issuerCertificate.getCertificate(), issuerPrivateKey, certificateCsr, crlApi, ocspApi, x509Api, System.currentTimeMillis());
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
        response.setCertificate(certificateCertificate);
        response.setPrivateKey(certificateKey.getPrivateKey());
        response.setPublicKey(certificateKey.getPublicKey());

        return response;
    }

    @Override
    @Transactional(rollbackFor = Throwable.class)
    public CertificateTlsGenerateResponse certificateTlsGenerate(User user, CertificateTlsGenerateRequest request, String crlApi, String ocspApi, String x509Api, YubicoPivSlotEnum issuerPivSlot) {
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
        PrivateKey issuerPrivateKey = null;
        if (issuerKey.getType() == KeyTypeEnum.ServerKeyJCE) {
            issuerPrivateKey = issuerKey.getPrivateKey();
        } else if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            Provider issuerProvider = YubicoProviderUtils.lookProvider(request.getIssuerUsbSlot());
            KeyStore issuerKeyStore = YubicoProviderUtils.lookupKeyStore(issuerProvider, request.getIssuerPin());
            issuerPrivateKey = YubicoProviderUtils.lookupPrivateKey(issuerKeyStore, issuerPivSlot, null);
        }

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

        KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);

        // certificate
        Key certificateKey = new Key();
        certificateKey.setType(KeyTypeEnum.ServerKeyJCE);
        certificateKey.setPublicKey(x509.getPublic());
        certificateKey.setPrivateKey(x509.getPrivate());
        certificateKey.setCreatedDatetime(new Date());
        certificateKey.setUser(user);
        this.keyRepository.save(certificateKey);

        X500Name certificateSubject = SubjectUtils.generate(
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

        PKCS10CertificationRequest certificateCsr = CsrUtils.generate(new KeyPair(certificateKey.getPublicKey(), certificateKey.getPrivateKey()), certificateSubject);
        X509Certificate certificateCertificate = CertificateUtils.generateTls(issuerCertificate.getCertificate(), issuerPrivateKey, certificateCsr, crlApi, ocspApi, x509Api, request.getIp(), request.getDns(), System.currentTimeMillis());
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
        response.setPrivkey(certificateKey.getPrivateKey());

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

}
