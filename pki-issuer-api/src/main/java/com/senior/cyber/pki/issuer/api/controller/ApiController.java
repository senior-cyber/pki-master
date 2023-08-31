package com.senior.cyber.pki.issuer.api.controller;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.x509.*;
import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.repository.CertificateRepository;
import com.senior.cyber.pki.dao.repository.KeyRepository;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
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

    @Autowired
    protected KeyRepository keyRepository;

    @Value("${api.crl}")
    protected String crlApi;

    @Value("${api.aia}")
    protected String aiaApi;

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
        Key issuingKey = null;
        if (request.getKey() > 0) {
            Optional<Key> optionalKey = keyRepository.findBySerial(request.getKey());
            issuingKey = optionalKey.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getKey() + " is not found"));
        } else {
            request.setKey(System.currentTimeMillis());
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setPublicKey(x509.getPublic());
            key.setPrivateKey(x509.getPrivate());
            key.setSerial(request.getKey());
            key.setCreatedDatetime(new Date());
            keyRepository.save(key);
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
        PKCS10CertificationRequest issuingCsr = CsrUtils.generate(new KeyPair(issuingKey.getPublicKey(), issuingKey.getPrivateKey()), issuingSubject);
        X509Certificate issuingCertificate = IssuerUtils.generate(issuerCertificate.getCertificate(), issuerCertificate.getKey().getPrivateKey(), issuingCsr, crlApi, aiaApi, request.getSerial());
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
        issuing.setSerial(issuingCertificate.getSerialNumber().longValueExact());
        issuing.setCreatedDatetime(new Date());
        issuing.setValidFrom(issuingCertificate.getNotBefore());
        issuing.setValidUntil(issuingCertificate.getNotAfter());
        issuing.setStatus(CertificateStatusEnum.Good);
        issuing.setType(CertificateTypeEnum.Root);
        issuing.setUser(null);
        certificateRepository.save(issuing);

        // crl
        Key crlKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setPrivateKey(x509.getPrivate());
            key.setPublicKey(x509.getPublic());
            key.setSerial(System.currentTimeMillis() + 1);
            key.setCreatedDatetime(new Date());
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
        X509Certificate crlCertificate = CrlUtils.generate(issuingCertificate, issuingKey.getPrivateKey(), crlCsr, System.currentTimeMillis() + 1);
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
        crl.setUser(null);
        certificateRepository.save(crl);

        // ocsp
        Key ocspKey = null;
        {
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setPrivateKey(x509.getPrivate());
            key.setPublicKey(x509.getPublic());
            key.setSerial(System.currentTimeMillis() + 2);
            key.setCreatedDatetime(new Date());
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
        X509Certificate ocspCertificate = OcspUtils.generate(issuingCertificate, issuingKey.getPrivateKey(), ocspCsr, System.currentTimeMillis() + 2);
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
        ocsp.setUser(null);
        certificateRepository.save(ocsp);

        issuing.setCrlCertificate(crl);
        issuing.setOcspCertificate(ocsp);
        certificateRepository.save(issuing);

        IssuerGenerateResponse response = new IssuerGenerateResponse();
        response.setSerial(issuing.getSerial());
        response.setKey(request.getKey());

        return ResponseEntity.ok(response);
    }

    @Transactional(rollbackFor = Throwable.class)
    @RequestMapping(path = "/certificate/common/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CertificateCommonGenerateResponse> certificateCommonGenerate(RequestEntity<CertificateCommonGenerateRequest> httpRequest) throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException {
        CertificateCommonGenerateRequest request = httpRequest.getBody();

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

        // certificate
        Key certificateKey = null;
        if (request.getKey() > 0) {
            Optional<Key> optionalKey = keyRepository.findBySerial(request.getKey());
            certificateKey = optionalKey.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getKey() + " is not found"));
        } else {
            request.setKey(System.currentTimeMillis());
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setPublicKey(x509.getPublic());
            key.setPrivateKey(x509.getPrivate());
            key.setSerial(request.getKey());
            key.setCreatedDatetime(new Date());
            keyRepository.save(key);
            certificateKey = key;
        }
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
        X509Certificate certificateCertificate = CertificateUtils.generateCommon(issuerCertificate.getCertificate(), issuerCertificate.getKey().getPrivateKey(), certificateCsr, crlApi, aiaApi, request.getSerial());
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
        certificate.setUser(null);
        certificateRepository.save(certificate);

        CertificateCommonGenerateResponse response = new CertificateCommonGenerateResponse();
        response.setSerial(certificate.getSerial());
        response.setKey(request.getKey());

        return ResponseEntity.ok(response);
    }

    @Transactional(rollbackFor = Throwable.class)
    @RequestMapping(path = "/certificate/tls/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CertificateTlsGenerateResponse> certificateTlsGenerate(RequestEntity<CertificateTlsGenerateRequest> httpRequest) throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException {
        CertificateTlsGenerateRequest request = httpRequest.getBody();

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
                if (!validator.isValid(dns)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid " + dns);
                }
            }
        }

        // certificate
        Key certificateKey = null;
        if (request.getKey() > 0) {
            Optional<Key> optionalKey = keyRepository.findBySerial(request.getKey());
            certificateKey = optionalKey.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getKey() + " is not found"));
        } else {
            request.setKey(System.currentTimeMillis());
            KeyPair x509 = KeyUtils.generate(KeyFormat.RSA);
            Key key = new Key();
            key.setPublicKey(x509.getPublic());
            key.setPrivateKey(x509.getPrivate());
            key.setSerial(request.getKey());
            key.setCreatedDatetime(new Date());
            keyRepository.save(key);
            certificateKey = key;
        }
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
        X509Certificate certificateCertificate = CertificateUtils.generateTls(issuerCertificate.getCertificate(), issuerCertificate.getKey().getPrivateKey(), certificateCsr, crlApi, aiaApi, request.getIp(), request.getDns(), request.getSerial());
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
        certificate.setUser(null);
        certificateRepository.save(certificate);

        CertificateTlsGenerateResponse response = new CertificateTlsGenerateResponse();
        response.setSerial(certificate.getSerial());

        return ResponseEntity.ok(response);
    }

}