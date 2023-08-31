package com.senior.cyber.pki.api.crl.controller;

import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.repository.CertificateRepository;
import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.joda.time.LocalDate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;
import java.util.Optional;

@RestController
public class CrlController {

    private static final Logger LOGGER = LoggerFactory.getLogger(CrlController.class);

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

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

    @RequestMapping(path = "/crl/{serial:.+}", method = RequestMethod.GET, produces = "application/pkix-crl")
    public ResponseEntity<byte[]> crlSerial(RequestEntity<Void> httpRequest, @PathVariable("serial") String _serial) throws CertificateException, IOException, NoSuchAlgorithmException, OperatorCreationException {
        LOGGER.info("PathInfo [{}] UserAgent [{}]", httpRequest.getUrl(), httpRequest.getHeaders().getFirst("User-Agent"));
        LocalDate now = LocalDate.now();
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        long serial = Long.parseLong(FilenameUtils.getBaseName(_serial));

        Optional<Certificate> optionalIssuerCertificate = certificateRepository.findBySerial(serial);
        Certificate issuerCertificate = optionalIssuerCertificate.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is not found"));

        List<Certificate> certificates = certificateRepository.findByIssuerCertificate(issuerCertificate);

        X509Certificate crlCertificate = issuerCertificate.getCrlCertificate().getCertificate();
        PrivateKey crlPrivateKey = issuerCertificate.getCrlCertificate().getKey().getPrivateKey();

        JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(crlCertificate, now.toDate());
        builder.setNextUpdate(now.plusWeeks(1).toDate());

        builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(crlCertificate.getPublicKey()));
        builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(System.currentTimeMillis())));

        for (Certificate certificate : certificates) {
            X509Certificate cert = certificate.getCertificate();
            if (certificate.getStatus() == CertificateStatusEnum.Good) {
                try {
                    cert.checkValidity();
                } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                    builder.addCRLEntry(cert.getSerialNumber(), certificate.getValidUntil(), CRLReason.cessationOfOperation);
                }
            } else {
                builder.addCRLEntry(cert.getSerialNumber(), certificate.getRevokedDate(), CRLReason.cessationOfOperation);
            }
        }

        String format = "";
        if (crlPrivateKey instanceof RSAPrivateKey) {
            format = "RSA";
        } else if (crlPrivateKey instanceof ECPrivateKey) {
            format = "ECDSA";
        } else if (crlPrivateKey instanceof DSAPrivateKey) {
            format = "DSA";
        }

        int shaSize = 256;
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
        contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner contentSigner = contentSignerBuilder.build(crlPrivateKey);

        X509CRLHolder holder = builder.build(contentSigner);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "inline");
        headers.add("Content-Type", "application/pkix-crl");
        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(holder.getEncoded());
    }

}
