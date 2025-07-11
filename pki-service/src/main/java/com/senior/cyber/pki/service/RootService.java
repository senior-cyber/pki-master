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
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class RootService {

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Transactional(rollbackFor = Throwable.class)
    public RootGenerateResponse rootGenerate(User user, RootGenerateRequest request) throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException, PKCSException {
        if (certificateRepository.findBySerial(request.getSerial()) != null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getSerial() + " is not available");
        }

        // root
        Key rootKey = null;
        if (request.getKey() > 0) {
            Key key = this.keyRepository.findBySerial(request.getKey());
            if (key == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getKey() + " is not found");
            }
            rootKey = key;
        } else {
            request.setKey(System.currentTimeMillis());
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setType(KeyTypeEnum.Plain);
            key.setPublicKey(x509.getPublic());
            key.setPrivateKey(x509.getPrivate());
            key.setSerial(request.getKey());
            key.setCreatedDatetime(new Date());
            key.setUser(user);
            keyRepository.save(key);
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
        PKCS10CertificationRequest rootCsr = CsrUtils.generate(new KeyPair(rootKey.getPublicKey(), rootKey.getPrivateKey()), rootSubject);
        X509Certificate rootCertificate = RootUtils.generate(new KeyPair(rootKey.getPublicKey(), rootKey.getPrivateKey()), rootCsr, request.getSerial());
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
        certificateRepository.save(root);

        // crl
        Key crlKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setType(KeyTypeEnum.Plain);
            key.setPrivateKey(x509.getPrivate());
            key.setPublicKey(x509.getPublic());
            key.setSerial(System.currentTimeMillis() + 1);
            key.setCreatedDatetime(new Date());
            key.setUser(user);
            keyRepository.save(key);
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
        X509Certificate crlCertificate = CrlUtils.generate(rootCertificate, rootKey.getPrivateKey(), crlCsr, System.currentTimeMillis() + 1);
        Certificate crl = new Certificate();
        crl.setIssuerCertificate(root);
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
        certificateRepository.save(crl);

        // ocsp
        Key ocspKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setType(KeyTypeEnum.Plain);
            key.setPrivateKey(x509.getPrivate());
            key.setPublicKey(x509.getPublic());
            key.setSerial(System.currentTimeMillis() + 2);
            key.setCreatedDatetime(new Date());
            key.setUser(user);
            keyRepository.save(key);
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
        X509Certificate ocspCertificate = OcspUtils.generate(rootCertificate, rootKey.getPrivateKey(), ocspCsr, System.currentTimeMillis() + 2);
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
        certificateRepository.save(ocsp);

        root.setCrlCertificate(crl);
        root.setOcspCertificate(ocsp);
        certificateRepository.save(root);

        RootGenerateResponse response = new RootGenerateResponse();
        response.setSerial(root.getSerial());
        response.setKey(rootKey.getSerial());

        return response;
    }
}
