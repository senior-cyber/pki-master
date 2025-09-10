package com.senior.cyber.pki.api.crl.controller;

import com.senior.cyber.pki.api.crl.ApiCrlApplication;
import com.senior.cyber.pki.common.x509.PrivateKeyUtils;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.joda.time.LocalDate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

@RestController
public class CrlController {

    private static final Logger LOGGER = LoggerFactory.getLogger(CrlController.class);

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Value("${api.x509}")
    protected String x509Api;

    @RequestMapping(path = "/crl/{serial:.+}", method = RequestMethod.GET, produces = "application/pkix-crl")
    public ResponseEntity<byte[]> crlSerial(HttpServletRequest request, RequestEntity<Void> httpRequest, @PathVariable("serial") String _serial) throws IOException, NoSuchAlgorithmException, OperatorCreationException {
        String remoteAddress = request.getRemoteAddr();
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            String[] temp = StringUtils.split(xForwardedFor, ",");
            remoteAddress = StringUtils.trim(temp[0]);
        }
        LocalDate now = LocalDate.now();
        LOGGER.info("[{}] [{}] PathInfo [{}] UserAgent [{}]", DateFormatUtils.ISO_8601_EXTENDED_DATETIME_TIME_ZONE_FORMAT.format(now.toDate()), remoteAddress, httpRequest.getUrl(), httpRequest.getHeaders().getFirst("User-Agent"));
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        long serial = -1;
        try {
            serial = Long.parseLong(FilenameUtils.getBaseName(_serial), 16);
        } catch (NumberFormatException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "serial is invalid");
        }

        Certificate issuerCertificate = this.certificateRepository.findBySerial(serial);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "certificate is not found");
        }

        switch (issuerCertificate.getType()) {
            case ROOT_CA, SUBORDINATE_CA, ISSUING_CA -> {
                Certificate _c = this.certificateRepository.findById(issuerCertificate.getCrlCertificate().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "crl certificate is not found"));
                if (_c.getStatus() == CertificateStatusEnum.Revoked) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "crl certificate have been revoked");
                }
                Key _k = this.keyRepository.findById(_c.getKey().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "crl key is not found"));
                if (_k.getStatus() == KeyStatusEnum.Revoked) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "crl key have been revoked");
                }

                X509Certificate crlCertificate = _c.getCertificate();
                PrivateKey crlPrivateKey = PrivateKeyUtils.convert(_k.getPrivateKey());

                Key _issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not found"));
                if (_issuerKey.getStatus() == KeyStatusEnum.Revoked) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key have been revoked");
                }

                String hex = String.format("%012X", issuerCertificate.getSerial());

                JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(crlCertificate, now.toDate());
                builder.setNextUpdate(now.plusWeeks(1).toDate());
                builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(_issuerKey.getPublicKey()));
                builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(System.currentTimeMillis())));
                builder.addExtension(Extension.issuerAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, this.x509Api + "/" + hex + ".der")));

                List<Certificate> certificates = this.certificateRepository.findByIssuerCertificate(issuerCertificate);
                for (Certificate certificate : certificates) {
                    X509Certificate cert = certificate.getCertificate();
                    switch (certificate.getStatus()) {
                        case Good -> {
                            try {
                                cert.checkValidity();
                            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                                builder.addCRLEntry(cert.getSerialNumber(), certificate.getValidUntil(), CRLReason.cessationOfOperation);
                            }
                        }
                        case Revoked -> {
                            if (certificate.getRevokedDate() == null) {
                                certificate.setRevokedDate(new Date());
                                certificateRepository.save(certificate);
                            }
                            builder.addCRLEntry(cert.getSerialNumber(), certificate.getRevokedDate(), CRLReason.cessationOfOperation);
                        }
                    }
                }

                String format = null;
                switch (_k.getKeyFormat()) {
                    case RSA -> {
                        format = "RSA";
                    }
                    case EC -> {
                        format = "ECDSA";
                    }
                }

                int shaSize = 256;
                JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
                contentSignerBuilder.setProvider(ApiCrlApplication.BC);
                ContentSigner contentSigner = contentSignerBuilder.build(crlPrivateKey);

                X509CRLHolder holder = builder.build(contentSigner);

                HttpHeaders headers = new HttpHeaders();
                headers.add("Content-Disposition", "inline");
                headers.add("Content-Type", "application/pkix-crl");
                return ResponseEntity.status(HttpStatus.OK).headers(headers).body(holder.getEncoded());
            }
            default -> {
                LOGGER.info("certificate type is {}", issuerCertificate.getType());
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "certificate is not type of [" + CertificateTypeEnum.ROOT_CA.name() + ", " + CertificateTypeEnum.SUBORDINATE_CA.name() + ", " + CertificateTypeEnum.ISSUING_CA.name() + "]");
            }
        }
    }

}
