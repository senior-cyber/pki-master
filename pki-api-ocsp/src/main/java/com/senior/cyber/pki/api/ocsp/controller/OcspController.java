package com.senior.cyber.pki.api.ocsp.controller;

import com.senior.cyber.pki.api.ocsp.ApiOcspApplication;
import com.senior.cyber.pki.common.x509.PrivateKeyUtils;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
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
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

@RestController
public class OcspController {

    private static final Logger LOGGER = LoggerFactory.getLogger(OcspController.class);

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @RequestMapping(path = "/ocsp/{serial}", method = RequestMethod.POST, consumes = "application/ocsp-request", produces = "application/ocsp-response")
    public ResponseEntity<byte[]> ocspSerial(HttpServletRequest request, RequestEntity<byte[]> httpRequest, @PathVariable("serial") String _serial) throws CertificateException, IOException, OperatorCreationException, OCSPException {
        String remoteAddress = request.getRemoteAddr();
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            String[] temp = StringUtils.split(xForwardedFor, ",");
            remoteAddress = StringUtils.trim(temp[0]);
        }
        Date now = new Date();
        LOGGER.info("[{}] [{}] PathInfo [{}] UserAgent [{}]", DateFormatUtils.ISO_8601_EXTENDED_DATETIME_TIME_ZONE_FORMAT.format(now), remoteAddress, httpRequest.getUrl(), httpRequest.getHeaders().getFirst("User-Agent"));

        byte[] requestBody = httpRequest.getBody();
        if (requestBody == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        long serial = -1;
        try {
            serial = Long.parseLong(_serial, 16);
        } catch (NumberFormatException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "serial is invalid");
        }

        Certificate issuerCertificate = certificateRepository.findBySerial(serial);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "certificate is not found");
        }

        switch (issuerCertificate.getType()) {
            case ROOT_CA, SUBORDINATE_CA, ISSUING_CA -> {
                Certificate _c = this.certificateRepository.findById(issuerCertificate.getOcspCertificate().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "ocsp certificate is not found"));
                if (_c.getStatus() == CertificateStatusEnum.Revoked) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "ocsp certificate have been revoked");
                }
                Key _k = this.keyRepository.findById(_c.getKey().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "ocsp key is not found"));
                if (_k.getStatus() == KeyStatusEnum.Revoked) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "ocsp key have been revoked");
                }

                X509Certificate ocspCertificate = _c.getCertificate();
                PrivateKey ocspPrivateKey = PrivateKeyUtils.convert(_k.getPrivateKey());

                String format = null;
                switch (_k.getKeyFormat()) {
                    case RSA -> {
                        format = "RSA";
                    }
                    case EC -> {
                        format = "ECDSA";
                    }
                }
                DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(ApiOcspApplication.BC).build();
                BasicOCSPRespBuilder ocspRespBuilder = new JcaBasicOCSPRespBuilder(ocspCertificate.getPublicKey(), digCalcProv.get(RespID.HASH_SHA1));

                OCSPReq ocspReq = new OCSPReq(requestBody);
                for (Req req : ocspReq.getRequestList()) {
                    CertificateID certId = req.getCertID();

                    DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
                    X509CertificateHolder issuerCert = new JcaX509CertificateHolder(issuerCertificate.getCertificate());
                    CertificateID respCertId = new CertificateID(digestCalculator, issuerCert, certId.getSerialNumber());

                    Certificate certificate = this.certificateRepository.findBySerial(certId.getSerialNumber().longValueExact());
                    if (certificate == null) {
                        ocspRespBuilder.addResponse(respCertId, new RevokedStatus(now, CRLReason.certificateHold));
                    } else {
                        switch (certificate.getStatus()) {
                            case Good -> {
                                X509Certificate cert = certificate.getCertificate();
                                try {
                                    cert.checkValidity();
                                    ocspRespBuilder.addResponse(respCertId, CertificateStatus.GOOD);
                                } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                                    if (certificate.getRevokedDate() == null) {
                                        certificate.setRevokedDate(new Date());
                                        certificateRepository.save(certificate);
                                        ocspRespBuilder.addResponse(respCertId, new RevokedStatus(certificate.getRevokedDate(), CRLReason.cessationOfOperation));
                                    }
                                }
                            }
                            case Revoked -> {
                                certificate.setRevokedDate(new Date());
                                certificateRepository.save(certificate);
                                ocspRespBuilder.addResponse(respCertId, new RevokedStatus(certificate.getRevokedDate(), CRLReason.cessationOfOperation));
                            }
                        }
                    }
                }

                int keySize = 256;
                JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + keySize + "WITH" + format);
                contentSignerBuilder.setProvider(ApiOcspApplication.BC);
                ContentSigner contentSigner = contentSignerBuilder.build(ocspPrivateKey);

                X509CertificateHolder holder = new JcaX509CertificateHolder(ocspCertificate);
                X509CertificateHolder[] chain = new X509CertificateHolder[]{holder};
                BasicOCSPResp resp = ocspRespBuilder.build(contentSigner, chain, now);
                OCSPRespBuilder respBuilder = new OCSPRespBuilder();
                OCSPResp ocspResp = respBuilder.build(OCSPRespBuilder.SUCCESSFUL, resp);
                HttpHeaders headers = new HttpHeaders();
                headers.add("Content-Disposition", "inline");
                headers.add("Content-Type", "application/ocsp-response");
                return ResponseEntity.status(HttpStatus.OK).headers(headers).body(ocspResp.getEncoded());
            }
            default -> {
                LOGGER.info("certificate type is {}", issuerCertificate.getType());
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "certificate is not type of [" + CertificateTypeEnum.ROOT_CA.name() + ", " + CertificateTypeEnum.SUBORDINATE_CA.name() + ", " + CertificateTypeEnum.ISSUING_CA.name() + "]");
            }
        }
    }

}
