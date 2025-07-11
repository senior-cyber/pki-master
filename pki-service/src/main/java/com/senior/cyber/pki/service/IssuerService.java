package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.IssuerGenerateRequest;
import com.senior.cyber.pki.common.dto.IssuerGenerateResponse;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.LocalDate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class IssuerService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Transactional(rollbackFor = Throwable.class)
    public IssuerGenerateResponse issuerGenerate(User user, IssuerGenerateRequest request, String crlApi, String aiaApi) {
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

        // issuing
        Key issuingKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setUser(user);
            key.setType(KeyTypeEnum.ServerKeyJCE);
            key.setPublicKey(x509.getPublic());
            key.setPrivateKey(x509.getPrivate());
            key.setCreatedDatetime(new Date());
            this.keyRepository.save(key);
            issuingKey = key;
        }

        X500Name issuingSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName(),
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        long serial = System.currentTimeMillis();
        PKCS10CertificationRequest issuingCsr = CsrUtils.generate(new KeyPair(issuingKey.getPublicKey(), issuingKey.getPrivateKey()), issuingSubject);
        X509Certificate issuingCertificate = IssuerUtils.generate(issuerCertificate.getCertificate(), issuerCertificate.getKey().getPrivateKey(), issuingCsr, crlApi, aiaApi, serial);
        Certificate issuing = new Certificate();
        issuing.setIssuerCertificate(issuerCertificate);
        issuing.setCountryCode(request.getCountry());
        issuing.setOrganization(request.getOrganization());
        issuing.setOrganizationalUnit(request.getOrganizationalUnit());
        issuing.setCommonName(request.getCommonName());
        issuing.setLocalityName(request.getLocality());
        issuing.setStateOrProvinceName(request.getProvince());
        issuing.setEmailAddress(request.getEmailAddress());
        issuing.setKey(issuingKey);
        issuing.setCertificate(issuingCertificate);
        issuing.setSerial(serial);
        issuing.setCreatedDatetime(new Date());
        issuing.setValidFrom(issuingCertificate.getNotBefore());
        issuing.setValidUntil(issuingCertificate.getNotAfter());
        issuing.setStatus(CertificateStatusEnum.Good);
        issuing.setType(CertificateTypeEnum.Issuer);
        issuing.setUser(user);
        this.certificateRepository.save(issuing);

        // crl
        Key crlKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setType(KeyTypeEnum.ServerKeyJCE);
            key.setUser(user);
            key.setPrivateKey(x509.getPrivate());
            key.setPublicKey(x509.getPublic());
            key.setCreatedDatetime(new Date());
            this.keyRepository.save(key);
            crlKey = key;
        }
        X500Name crlSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName() + " CRL",
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        PKCS10CertificationRequest crlCsr = CsrUtils.generate(new KeyPair(crlKey.getPublicKey(), crlKey.getPrivateKey()), crlSubject);
        X509Certificate crlCertificate = IssuerUtils.generateCrlCertificate(issuingCertificate, issuingKey.getPrivateKey(), crlCsr, serial + 1);
        Certificate crl = new Certificate();
        crl.setIssuerCertificate(issuing);
        crl.setCountryCode(request.getCountry());
        crl.setOrganization(request.getOrganization());
        crl.setOrganizationalUnit(request.getOrganizationalUnit());
        crl.setCommonName(request.getCommonName() + " CRL");
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
        crl.setType(CertificateTypeEnum.Crl);
        crl.setUser(user);
        this.certificateRepository.save(crl);

        // ocsp
        Key ocspKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setUser(user);
            key.setType(KeyTypeEnum.ServerKeyJCE);
            key.setPrivateKey(x509.getPrivate());
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
        PKCS10CertificationRequest ocspCsr = CsrUtils.generate(new KeyPair(ocspKey.getPublicKey(), ocspKey.getPrivateKey()), ocspSubject);
        X509Certificate ocspCertificate = IssuerUtils.generateOcspCertificate(issuingCertificate, issuingKey.getPrivateKey(), ocspCsr, serial + 2);
        Certificate ocsp = new Certificate();
        ocsp.setIssuerCertificate(issuing);
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
        ocsp.setType(CertificateTypeEnum.Ocsp);
        ocsp.setUser(user);
        this.certificateRepository.save(ocsp);

        issuing.setCrlCertificate(crl);
        issuing.setOcspCertificate(ocsp);
        this.certificateRepository.save(issuing);

        IssuerGenerateResponse response = new IssuerGenerateResponse();
        response.setId(issuing.getId());
        response.setCertificate(issuingCertificate);
        response.setPublicKey(issuingKey.getPublicKey());
        response.setPrivateKey(issuingKey.getPrivateKey());
        response.setOcspCertificate(ocspCertificate);
        response.setOcspPublicKey(ocspCertificate.getPublicKey());
        response.setOcspPrivateKey(ocspKey.getPrivateKey());
        response.setCrlCertificate(crlCertificate);
        response.setCrlPublicKey(crlKey.getPublicKey());
        response.setCrlPrivateKey(crlKey.getPrivateKey());

        return response;
    }

}
