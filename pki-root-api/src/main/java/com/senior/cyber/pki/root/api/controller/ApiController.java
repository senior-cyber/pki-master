package com.senior.cyber.pki.root.api.controller;

import com.senior.cyber.pki.common.dto.IssuerGenerateRequest;
import com.senior.cyber.pki.common.dto.IssuerGenerateResponse;
import com.senior.cyber.pki.common.dto.RootGenerateRequest;
import com.senior.cyber.pki.common.dto.RootGenerateResponse;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.repository.CertificateRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.LocalDate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Optional;

@RestController
public class ApiController {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiController.class);

    private static final String[] HEADERS_TO_TRY = {
            "X-Forwarded-For",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED",
            "HTTP_VIA",
            "REMOTE_ADDR"};

    @Autowired
    protected CertificateRepository certificateRepository;

    @Value("${api.crl}")
    protected String crlApi;

    @Value("${api.aia}")
    protected String aiaApi;

    @Transactional(rollbackFor = Throwable.class)
    @RequestMapping(path = "/root/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<RootGenerateResponse> rootGenerate(RequestEntity<RootGenerateRequest> httpRequest) throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException {
        RootGenerateRequest request = httpRequest.getBody();

        Optional<Certificate> optionalCertificate = certificateRepository.findBySerial(request.getSerial());
        if (optionalCertificate.isPresent()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getSerial() + " is not available");
        }

        // root
        KeyPair rootKey = KeyUtils.generate(KeyFormat.RSA);
        X500Name rootSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName(),
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        PKCS10CertificationRequest rootCsr = CsrUtils.generate(rootKey, rootSubject);
        X509Certificate rootCertificate = RootUtils.generate(rootKey, rootCsr, request.getSerial());
        Certificate root = new Certificate();
        root.setCountryCode(request.getCountry());
        root.setOrganization(request.getOrganization());
        root.setOrganizationalUnit(request.getOrganizationalUnit());
        root.setCommonName(request.getCommonName());
        root.setLocalityName(request.getLocality());
        root.setStateOrProvinceName(request.getProvince());
        root.setEmailAddress(request.getEmailAddress());
        root.setPrivateKey(rootKey.getPrivate());
        root.setCertificate(rootCertificate);
        root.setSerial(request.getSerial());
        root.setCreatedDatetime(new Date());
        root.setValidFrom(rootCertificate.getNotBefore());
        root.setValidUntil(rootCertificate.getNotAfter());
        root.setStatus(CertificateStatusEnum.Good);
        root.setType(CertificateTypeEnum.Root);
        root.setUser(null);
        certificateRepository.save(root);

        // crl
        KeyPair crlKey = KeyUtils.generate(KeyFormat.RSA);
        X500Name crlSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName() + " CRL",
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        PKCS10CertificationRequest crlCsr = CsrUtils.generate(crlKey, crlSubject);
        X509Certificate crlCertificate = CrlUtils.generate(rootCertificate, rootKey.getPrivate(), crlCsr, request.getSerial() + 1);
        Certificate crl = new Certificate();
        crl.setIssuerCertificate(root);
        crl.setCountryCode(request.getCountry());
        crl.setOrganization(request.getOrganization());
        crl.setOrganizationalUnit(request.getOrganizationalUnit());
        crl.setCommonName(request.getCommonName() + " CRL");
        crl.setLocalityName(request.getLocality());
        crl.setStateOrProvinceName(request.getProvince());
        crl.setEmailAddress(request.getEmailAddress());
        crl.setPrivateKey(crlKey.getPrivate());
        crl.setCertificate(crlCertificate);
        crl.setSerial(request.getSerial() + 1);
        crl.setCreatedDatetime(new Date());
        crl.setValidFrom(crlCertificate.getNotBefore());
        crl.setValidUntil(crlCertificate.getNotAfter());
        crl.setStatus(CertificateStatusEnum.Good);
        crl.setType(CertificateTypeEnum.Crl);
        crl.setUser(null);
        certificateRepository.save(crl);

        // ocsp
        KeyPair ocspKey = KeyUtils.generate(KeyFormat.RSA);
        X500Name ocspSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName() + " OCSP",
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        PKCS10CertificationRequest ocspCsr = CsrUtils.generate(ocspKey, ocspSubject);
        X509Certificate ocspCertificate = CrlUtils.generate(rootCertificate, rootKey.getPrivate(), ocspCsr, request.getSerial() + 2);
        Certificate ocsp = new Certificate();
        ocsp.setIssuerCertificate(root);
        ocsp.setCountryCode(request.getCountry());
        ocsp.setOrganization(request.getOrganization());
        ocsp.setOrganizationalUnit(request.getOrganizationalUnit());
        ocsp.setCommonName(request.getCommonName() + " OCSP");
        ocsp.setLocalityName(request.getLocality());
        ocsp.setStateOrProvinceName(request.getProvince());
        ocsp.setEmailAddress(request.getEmailAddress());
        ocsp.setPrivateKey(ocspKey.getPrivate());
        ocsp.setCertificate(ocspCertificate);
        ocsp.setSerial(request.getSerial() + 2);
        ocsp.setCreatedDatetime(new Date());
        ocsp.setValidFrom(ocspCertificate.getNotBefore());
        ocsp.setValidUntil(ocspCertificate.getNotAfter());
        ocsp.setStatus(CertificateStatusEnum.Good);
        ocsp.setType(CertificateTypeEnum.Ocsp);
        ocsp.setUser(null);
        certificateRepository.save(ocsp);

        root.setCrlCertificate(crl);
        root.setOcspCertificate(ocsp);
        certificateRepository.save(root);

        RootGenerateResponse response = new RootGenerateResponse();
        response.setSerial(root.getSerial());
        response.setOcspSerial(ocsp.getSerial());
        response.setCrlSerial(crl.getSerial());

        return ResponseEntity.ok(response);
    }

    @Transactional(rollbackFor = Throwable.class)
    @RequestMapping(path = "/issuer/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<IssuerGenerateResponse> issuerGenerate(RequestEntity<IssuerGenerateRequest> httpRequest) throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException {
        IssuerGenerateRequest request = httpRequest.getBody();

        Optional<Certificate> optionalCertificate = certificateRepository.findBySerial(request.getSerial());
        if (optionalCertificate.isPresent()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getSerial() + " is not available");
        }

        Date now = LocalDate.now().toDate();

        Optional<Certificate> optionalIssuerCertificate = certificateRepository.findBySerial(request.getIssuerSerial());
        Certificate issuerCertificate = optionalIssuerCertificate.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerSerial() + " is not found"));
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Root && issuerCertificate.getType() != CertificateTypeEnum.Issuer) ||
                issuerCertificate.getValidFrom().before(now) ||
                issuerCertificate.getValidUntil().before(now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerSerial() + " is not valid");
        }

        // issuing
        KeyPair issuingKey = KeyUtils.generate(KeyFormat.RSA);
        X500Name issuingSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName(),
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        PKCS10CertificationRequest issuingCsr = CsrUtils.generate(issuingKey, issuingSubject);
        X509Certificate issuingCertificate = IssuerUtils.generate(issuerCertificate.getCertificate(), issuerCertificate.getPrivateKey(), issuingCsr, crlApi, aiaApi, request.getSerial());
        Certificate issuing = new Certificate();
        issuing.setIssuerCertificate(issuerCertificate);
        issuing.setCountryCode(request.getCountry());
        issuing.setOrganization(request.getOrganization());
        issuing.setOrganizationalUnit(request.getOrganizationalUnit());
        issuing.setCommonName(request.getCommonName());
        issuing.setLocalityName(request.getLocality());
        issuing.setStateOrProvinceName(request.getProvince());
        issuing.setEmailAddress(request.getEmailAddress());
        issuing.setPrivateKey(issuingKey.getPrivate());
        issuing.setCertificate(issuingCertificate);
        issuing.setSerial(request.getSerial());
        issuing.setCreatedDatetime(new Date());
        issuing.setValidFrom(issuingCertificate.getNotBefore());
        issuing.setValidUntil(issuingCertificate.getNotAfter());
        issuing.setStatus(CertificateStatusEnum.Good);
        issuing.setType(CertificateTypeEnum.Root);
        issuing.setUser(null);
        certificateRepository.save(issuing);

        // crl
        KeyPair crlKey = KeyUtils.generate(KeyFormat.RSA);
        X500Name crlSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName() + " CRL",
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        PKCS10CertificationRequest crlCsr = CsrUtils.generate(crlKey, crlSubject);
        X509Certificate crlCertificate = CrlUtils.generate(issuingCertificate, issuingKey.getPrivate(), crlCsr, request.getSerial() + 1);
        Certificate crl = new Certificate();
        crl.setIssuerCertificate(issuing);
        crl.setCountryCode(request.getCountry());
        crl.setOrganization(request.getOrganization());
        crl.setOrganizationalUnit(request.getOrganizationalUnit());
        crl.setCommonName(request.getCommonName() + " CRL");
        crl.setLocalityName(request.getLocality());
        crl.setStateOrProvinceName(request.getProvince());
        crl.setEmailAddress(request.getEmailAddress());
        crl.setPrivateKey(crlKey.getPrivate());
        crl.setCertificate(crlCertificate);
        crl.setSerial(request.getSerial() + 1);
        crl.setCreatedDatetime(new Date());
        crl.setValidFrom(crlCertificate.getNotBefore());
        crl.setValidUntil(crlCertificate.getNotAfter());
        crl.setStatus(CertificateStatusEnum.Good);
        crl.setType(CertificateTypeEnum.Crl);
        crl.setUser(null);
        certificateRepository.save(crl);

        // ocsp
        KeyPair ocspKey = KeyUtils.generate(KeyFormat.RSA);
        X500Name ocspSubject = SubjectUtils.generate(
                request.getCountry(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getCommonName() + " OCSP",
                request.getLocality(),
                request.getProvince(),
                request.getEmailAddress()
        );
        PKCS10CertificationRequest ocspCsr = CsrUtils.generate(ocspKey, ocspSubject);
        X509Certificate ocspCertificate = CrlUtils.generate(issuingCertificate, issuingKey.getPrivate(), ocspCsr, request.getSerial() + 2);
        Certificate ocsp = new Certificate();
        ocsp.setIssuerCertificate(issuing);
        ocsp.setCountryCode(request.getCountry());
        ocsp.setOrganization(request.getOrganization());
        ocsp.setOrganizationalUnit(request.getOrganizationalUnit());
        ocsp.setCommonName(request.getCommonName() + " OCSP");
        ocsp.setLocalityName(request.getLocality());
        ocsp.setStateOrProvinceName(request.getProvince());
        ocsp.setEmailAddress(request.getEmailAddress());
        ocsp.setPrivateKey(ocspKey.getPrivate());
        ocsp.setCertificate(ocspCertificate);
        ocsp.setSerial(request.getSerial() + 2);
        ocsp.setCreatedDatetime(new Date());
        ocsp.setValidFrom(ocspCertificate.getNotBefore());
        ocsp.setValidUntil(ocspCertificate.getNotAfter());
        ocsp.setStatus(CertificateStatusEnum.Good);
        ocsp.setType(CertificateTypeEnum.Ocsp);
        ocsp.setUser(null);
        certificateRepository.save(ocsp);

        issuing.setCrlCertificate(crl);
        issuing.setOcspCertificate(ocsp);
        certificateRepository.save(issuing);

        IssuerGenerateResponse response = new IssuerGenerateResponse();
        response.setSerial(issuing.getSerial());
        response.setOcspSerial(ocsp.getSerial());
        response.setCrlSerial(crl.getSerial());

        return ResponseEntity.ok(response);
    }

}
