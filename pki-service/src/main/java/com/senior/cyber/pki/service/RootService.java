package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.dto.RootGenerateRequest;
import com.senior.cyber.pki.common.dto.RootGenerateResponse;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class RootService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Transactional(rollbackFor = Throwable.class)
    public RootGenerateResponse rootGenerate(User user, RootGenerateRequest request) {

        // root
        Key rootKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setType(KeyTypeEnum.ServerKeyJCE);
            key.setPublicKey(x509.getPublic());
            key.setPrivateKey(x509.getPrivate());
            key.setCreatedDatetime(new Date());
            key.setUser(user);
            this.keyRepository.save(key);
            rootKey = key;
        }

        X500Name rootSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName(),
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        X509Certificate rootCertificate = RootUtils.generate(rootKey.getPrivateKey(), rootKey.getPublicKey(), rootSubject);
        Certificate root = new Certificate();
        root.setCountryCode(request.getCountry());
        root.setOrganization(request.getOrganization());
        root.setOrganizationalUnit(request.getOrganizationalUnit());
        root.setCommonName(request.getCommonName());
        root.setLocalityName(request.getLocality());
        root.setStateOrProvinceName(request.getProvince());
        root.setEmailAddress(request.getEmailAddress());
        root.setKey(rootKey);
        root.setCertificate(rootCertificate);
        root.setSerial(rootCertificate.getSerialNumber().longValueExact());
        root.setCreatedDatetime(new Date());
        root.setValidFrom(rootCertificate.getNotBefore());
        root.setValidUntil(rootCertificate.getNotAfter());
        root.setStatus(CertificateStatusEnum.Good);
        root.setType(CertificateTypeEnum.Root);
        root.setUser(user);
        this.certificateRepository.save(root);

        // crl
        Key crlKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setType(KeyTypeEnum.ServerKeyJCE);
            key.setPrivateKey(x509.getPrivate());
            key.setPublicKey(x509.getPublic());
            key.setCreatedDatetime(new Date());
            key.setUser(user);
            this.keyRepository.save(key);
            crlKey = key;
        }
        X500Name crlSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName(),
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        PKCS10CertificationRequest crlCsr = CsrUtils.generate(new KeyPair(crlKey.getPublicKey(), crlKey.getPrivateKey()), crlSubject);
        X509Certificate crlCertificate = IssuerUtils.generateCrlCertificate(rootCertificate, rootKey.getPrivateKey(), crlCsr, root.getSerial() + 1);
        Certificate crl = new Certificate();
        crl.setIssuerCertificate(root);
        crl.setCountryCode(request.getCountry());
        crl.setOrganization(request.getOrganization());
        crl.setOrganizationalUnit(request.getOrganizationalUnit());
        crl.setCommonName(request.getCommonName() );
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
            key.setType(KeyTypeEnum.ServerKeyJCE);
            key.setPrivateKey(x509.getPrivate());
            key.setPublicKey(x509.getPublic());
            key.setCreatedDatetime(new Date());
            key.setUser(user);
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
        X509Certificate ocspCertificate = IssuerUtils.generateOcspCertificate(rootCertificate, rootKey.getPrivateKey(), ocspCsr, root.getSerial() + 2);
        Certificate ocsp = new Certificate();
        ocsp.setIssuerCertificate(root);
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

        root.setCrlCertificate(crl);
        root.setOcspCertificate(ocsp);
        this.certificateRepository.save(root);

        RootGenerateResponse response = new RootGenerateResponse();
        response.setId(root.getId());
        response.setCertificate(rootCertificate);
        response.setPublicKey(rootKey.getPublicKey());
        response.setPrivateKey(rootKey.getPrivateKey());
        response.setOcspCertificate(ocspCertificate);
        response.setOcspPublicKey(ocspCertificate.getPublicKey());
        response.setOcspPrivateKey(ocspKey.getPrivateKey());
        response.setCrlCertificate(crlCertificate);
        response.setCrlPublicKey(crlKey.getPublicKey());
        response.setCrlPrivateKey(crlKey.getPrivateKey());

        return response;
    }
}
