package com.senior.cyber.pki.api.controller;

import com.senior.cyber.pki.api.repository.CertificateRepository;
import com.senior.cyber.pki.api.repository.IntermediateRepository;
import com.senior.cyber.pki.api.repository.RootRepository;
import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.Intermediate;
import com.senior.cyber.pki.dao.entity.Root;
import com.senior.cyber.frmk.common.pki.CertificateUtils;
import com.senior.cyber.frmk.common.pki.PrivateKeyUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.joda.time.LocalDate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping(path = "/pki")
public class PkiController {

    private static final Logger LOGGER = LoggerFactory.getLogger(PkiController.class);

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
    protected IntermediateRepository intermediateRepository;

    @Autowired
    protected RootRepository rootRepository;

    @Autowired
    protected CertificateRepository certificateRepository;

    @RequestMapping(path = "/intermediate/{serial:.+}", method = RequestMethod.GET, produces = "application/pkix-cert")
    public ResponseEntity<byte[]> intermediate(@PathVariable("serial") String serial, HttpServletRequest request) throws CertificateException, IOException {
        LOGGER.info("Client [{}] PathInfo [{}] UserAgent [{}]", getClientIpAddress(request), request.getPathInfo(), request.getHeader("User-Agent"));
        Optional<Intermediate> optionalIntermediate = intermediateRepository.findBySerial(Long.parseLong(FilenameUtils.getBaseName(serial)));
        Intermediate intermediate = optionalIntermediate.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        X509Certificate certificate = CertificateUtils.read(intermediate.getCertificate());
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "inline");
        headers.add("Content-Type", "application/pkix-cert");
        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(certificate.getEncoded());
    }

    @RequestMapping(path = "/root/{serial:.+}", method = RequestMethod.GET, produces = "application/pkix-cert")
    public ResponseEntity<byte[]> root(@PathVariable("serial") String serial, HttpServletRequest request) throws CertificateException, IOException {
        LOGGER.info("Client [{}] PathInfo [{}] UserAgent [{}]", getClientIpAddress(request), request.getPathInfo(), request.getHeader("User-Agent"));
        Optional<Root> optionalRoot = rootRepository.findBySerial(Long.parseLong(FilenameUtils.getBaseName(serial)));
        Root root = optionalRoot.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        X509Certificate certificate = CertificateUtils.read(root.getCertificate());
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "inline");
        headers.add("Content-Type", "application/pkix-cert");
        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(certificate.getEncoded());
    }

    @RequestMapping(path = "/crl/root/{serial:.+}", method = RequestMethod.GET, produces = "application/pkix-crl")
    public ResponseEntity<byte[]> crlRoot(@PathVariable("serial") String serial, HttpServletRequest request) throws CertificateException, IOException, NoSuchAlgorithmException, OperatorCreationException {
        LOGGER.info("Client [{}] PathInfo [{}] UserAgent [{}]", getClientIpAddress(request), request.getPathInfo(), request.getHeader("User-Agent"));
        LocalDate now = LocalDate.now();
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        Optional<Root> optionalRoot = rootRepository.findBySerial(Long.parseLong(FilenameUtils.getBaseName(serial)));
        Root root = optionalRoot.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        List<Intermediate> intermediates = intermediateRepository.findByRoot(root);

        X509Certificate issuerCertificate = CertificateUtils.read(root.getCertificate());
        PrivateKey issuerPrivateKey = PrivateKeyUtils.read(root.getPrivateKey());

        JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(issuerCertificate, now.toDate());
        builder.setNextUpdate(now.plusWeeks(1).toDate());

        builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
        builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(System.currentTimeMillis())).getEncoded());

        for (Intermediate intermediate : intermediates) {
            X509Certificate cert = CertificateUtils.read(intermediate.getCertificate());
            if ("Good".equals(intermediate.getStatus())) {
                try {
                    cert.checkValidity();
                } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                    builder.addCRLEntry(cert.getSerialNumber(), intermediate.getValidUntil(), CRLReason.cessationOfOperation);
                }
            } else {
                builder.addCRLEntry(cert.getSerialNumber(), intermediate.getRevokedDate(), CRLReason.cessationOfOperation);
            }
        }

        int keySize = 256;
        keySize = 1;
        String format = "";
        if (issuerPrivateKey instanceof RSAPrivateKey) {
            format = "RSA";
        } else if (issuerPrivateKey instanceof ECPrivateKey) {
            format = "ECDSA";
        } else if (issuerPrivateKey instanceof DSAPrivateKey) {
            format = "DSA";
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + keySize + "WITH" + format);
        ContentSigner contentSigner = contentSignerBuilder.build(issuerPrivateKey);

        X509CRLHolder holder = builder.build(contentSigner);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "inline");
        headers.add("Content-Type", "application/pkix-crl");
        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(holder.getEncoded());
    }

    @RequestMapping(path = "/crl/intermediate/{serial:.+}", method = RequestMethod.GET, produces = "application/pkix-crl")
    public ResponseEntity<byte[]> crlIntermediate(@PathVariable("serial") String serial, HttpServletRequest request) throws CertificateException, IOException, NoSuchAlgorithmException, OperatorCreationException {
        LOGGER.info("Client [{}] PathInfo [{}] UserAgent [{}]", getClientIpAddress(request), request.getPathInfo(), request.getHeader("User-Agent"));
        LocalDate now = LocalDate.now();
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        Optional<Intermediate> optionalIntermediate = intermediateRepository.findBySerial(Long.parseLong(FilenameUtils.getBaseName(serial)));
        Intermediate intermediate = optionalIntermediate.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        List<Certificate> certificates = certificateRepository.findByIntermediate(intermediate);

        X509Certificate issuerCertificate = CertificateUtils.read(intermediate.getCertificate());
        PrivateKey issuerPrivateKey = PrivateKeyUtils.read(intermediate.getPrivateKey());

        JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(issuerCertificate, now.toDate());
        builder.setNextUpdate(now.plusWeeks(1).toDate());

        builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
        builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(System.currentTimeMillis())).getEncoded());

        for (Certificate certificate : certificates) {
            X509Certificate cert = CertificateUtils.read(certificate.getCertificate());
            if ("Good".equals(certificate.getStatus())) {
                try {
                    cert.checkValidity();
                } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                    builder.addCRLEntry(cert.getSerialNumber(), certificate.getValidUntil(), CRLReason.cessationOfOperation);
                }
            } else {
                builder.addCRLEntry(cert.getSerialNumber(), certificate.getRevokedDate(), CRLReason.cessationOfOperation);
            }
        }

        int keySize = 256;
        keySize = 1;
        String format = "";
        if (issuerPrivateKey instanceof RSAPrivateKey) {
            format = "RSA";
        } else if (issuerPrivateKey instanceof ECPrivateKey) {
            format = "ECDSA";
        } else if (issuerPrivateKey instanceof DSAPrivateKey) {
            format = "DSA";
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + keySize + "WITH" + format);
        ContentSigner contentSigner = contentSignerBuilder.build(issuerPrivateKey);

        X509CRLHolder holder = builder.build(contentSigner);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "inline");
        headers.add("Content-Type", "application/pkix-crl");
        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(holder.getEncoded());
    }

    @RequestMapping(path = "/ocsp/root/{serial}", method = RequestMethod.POST, consumes = "application/ocsp-request", produces = "application/ocsp-response")
    public ResponseEntity<byte[]> ocspRoot(@PathVariable("serial") String serial, HttpServletRequest request) throws CertificateException, IOException, OperatorCreationException, OCSPException {
        LOGGER.info("Client [{}] PathInfo [{}] UserAgent [{}]", getClientIpAddress(request), request.getPathInfo(), request.getHeader("User-Agent"));
        Optional<Root> optionalRoot = rootRepository.findBySerial(Long.parseLong(FilenameUtils.getBaseName(serial)));
        Root root = optionalRoot.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        X509Certificate issuerCertificate = CertificateUtils.read(root.getCertificate());
        PrivateKey issuerPrivateKey = PrivateKeyUtils.read(root.getPrivateKey());

        OCSPReq ocspReq = new OCSPReq(IOUtils.toByteArray(request.getInputStream()));

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build();

        int keySize = 256;
        keySize = 1;
        String format = "";
        if (issuerPrivateKey instanceof RSAPrivateKey) {
            format = "RSA";
        } else if (issuerPrivateKey instanceof ECPrivateKey) {
            format = "ECDSA";
        } else if (issuerPrivateKey instanceof DSAPrivateKey) {
            format = "DSA";
        }

        Date now = LocalDate.now().toDate();

        JcaBasicOCSPRespBuilder ocspRespBuilder = new JcaBasicOCSPRespBuilder(issuerCertificate.getPublicKey(), digCalcProv.get(RespID.HASH_SHA1));
        for (Req req : ocspReq.getRequestList()) {
            Optional<Intermediate> optionalIntermediate = this.intermediateRepository.findBySerialAndRoot(req.getCertID().getSerialNumber().longValueExact(), root);
            Intermediate intermediate = optionalIntermediate.orElse(null);
            if (intermediate == null) {
                ocspRespBuilder.addResponse(req.getCertID(), new RevokedStatus(now, CRLReason.certificateHold));
            } else {
                if ("Good".equals(intermediate.getStatus())) {
                    X509Certificate cert = CertificateUtils.read(intermediate.getCertificate());
                    try {
                        cert.checkValidity();
                        ocspRespBuilder.addResponse(req.getCertID(), CertificateStatus.GOOD);
                    } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                        ocspRespBuilder.addResponse(req.getCertID(), new RevokedStatus(intermediate.getRevokedDate(), CRLReason.cessationOfOperation));
                    }
                } else {
                    ocspRespBuilder.addResponse(req.getCertID(), new RevokedStatus(intermediate.getRevokedDate(), CRLReason.cessationOfOperation));
                }
            }
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + keySize + "WITH" + format);
        ContentSigner contentSigner = contentSignerBuilder.build(issuerPrivateKey);

        BasicOCSPResp resp = ocspRespBuilder.build(contentSigner, new X509CertificateHolder[]{new JcaX509CertificateHolder(issuerCertificate)}, now);
        OCSPRespBuilder respBuilder = new OCSPRespBuilder();
        OCSPResp ocspResp = respBuilder.build(OCSPRespBuilder.SUCCESSFUL, resp);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "inline");
        headers.add("Content-Type", "application/ocsp-response");
        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(ocspResp.getEncoded());
    }

    @RequestMapping(path = "/ocsp/intermediate/{serial}", method = RequestMethod.POST, consumes = "application/ocsp-request", produces = "application/ocsp-response")
    public ResponseEntity<byte[]> ocspIntermediate(@PathVariable("serial") String serial, HttpServletRequest request) throws CertificateException, IOException, OperatorCreationException, OCSPException {
        LOGGER.info("Client [{}] PathInfo [{}] UserAgent [{}]", getClientIpAddress(request), request.getPathInfo(), request.getHeader("User-Agent"));
        Optional<Intermediate> optionalIntermediate = intermediateRepository.findBySerial(Long.parseLong(FilenameUtils.getBaseName(serial)));
        Intermediate intermediate = optionalIntermediate.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        Root root = intermediate.getRoot();
        X509Certificate rootCertificate = CertificateUtils.read(root.getCertificate());
        X509Certificate issuerCertificate = CertificateUtils.read(intermediate.getCertificate());
        PrivateKey issuerPrivateKey = PrivateKeyUtils.read(intermediate.getPrivateKey());

        Date now = LocalDate.now().toDate();

        OCSPReq ocspReq = new OCSPReq(IOUtils.toByteArray(request.getInputStream()));

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build();

        int keySize = 256;
        // keySize = 1;
        String format = "";
        if (issuerPrivateKey instanceof RSAPrivateKey) {
            format = "RSA";
        } else if (issuerPrivateKey instanceof ECPrivateKey) {
            format = "ECDSA";
        } else if (issuerPrivateKey instanceof DSAPrivateKey) {
            format = "DSA";
        }

        JcaBasicOCSPRespBuilder ocspRespBuilder = new JcaBasicOCSPRespBuilder(issuerCertificate.getPublicKey(), digCalcProv.get(RespID.HASH_SHA1));
        for (Req req : ocspReq.getRequestList()) {
            Optional<Certificate> optionalCertificate = this.certificateRepository.findBySerialAndIntermediate(req.getCertID().getSerialNumber().longValueExact(), intermediate);
            Certificate certificate = optionalCertificate.orElse(null);
            if (certificate == null) {
                ocspRespBuilder.addResponse(req.getCertID(), new RevokedStatus(now, CRLReason.certificateHold));
            } else {
                if ("Good".equals(certificate.getStatus())) {
                    X509Certificate cert = CertificateUtils.read(certificate.getCertificate());
                    try {
                        cert.checkValidity();
                        ocspRespBuilder.addResponse(req.getCertID(), CertificateStatus.GOOD);
                    } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                        ocspRespBuilder.addResponse(req.getCertID(), new RevokedStatus(intermediate.getRevokedDate(), CRLReason.cessationOfOperation));
                    }
                } else {
                    ocspRespBuilder.addResponse(req.getCertID(), new RevokedStatus(certificate.getRevokedDate(), CRLReason.cessationOfOperation));
                }
            }
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + keySize + "WITH" + format);
        ContentSigner contentSigner = contentSignerBuilder.build(issuerPrivateKey);


        BasicOCSPResp resp = ocspRespBuilder.build(contentSigner, new X509CertificateHolder[]{new JcaX509CertificateHolder(issuerCertificate), new JcaX509CertificateHolder(rootCertificate)}, now);
        OCSPRespBuilder respBuilder = new OCSPRespBuilder();
        OCSPResp ocspResp = respBuilder.build(OCSPRespBuilder.SUCCESSFUL, resp);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "inline");
        headers.add("Content-Type", "application/ocsp-response");
        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(ocspResp.getEncoded());
    }

    protected String getClientIpAddress(HttpServletRequest request) {
        for (String header : HEADERS_TO_TRY) {
            String ip = request.getHeader(header);
            if (ip != null && !"".equals(ip) && !"unknown".equalsIgnoreCase(ip)) {
                return ip;
            }
        }
        return request.getRemoteAddr();
    }

}
