package com.senior.cyber.pki.api.ocsp.controller;

import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
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
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;

@RestController
public class OcspController {

    private static final Logger LOGGER = LoggerFactory.getLogger(OcspController.class);

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @RequestMapping(path = "/ocsp/{serial}", method = RequestMethod.POST, consumes = "application/ocsp-request", produces = "application/ocsp-response")
    public ResponseEntity<byte[]> ocspSerial(RequestEntity<byte[]> httpRequest, @PathVariable("serial") String _serial) throws CertificateException, IOException, OperatorCreationException, OCSPException {
        LOGGER.info("PathInfo [{}] UserAgent [{}]", httpRequest.getUrl(), httpRequest.getHeaders().getFirst("User-Agent"));
        long serial = -1;
        try {
            serial = Long.parseLong(_serial, 16);
        } catch (NumberFormatException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is invalid");
        }

        Certificate issuerCertificate = certificateRepository.findBySerial(serial);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is not found");
        }

        Certificate _c = this.certificateRepository.findById(issuerCertificate.getOcspCertificate().getId()).orElse(null);
        if (_c == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is not found");
        }
        Key _k = this.keyRepository.findById(_c.getKey().getId()).orElse(null);
        if (_k == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is not found");
        }
        X509Certificate ocspCertificate = _c.getCertificate();
        PrivateKey ocspPrivateKey = _k.getPrivateKey();

        byte[] requestBody = httpRequest.getBody();
        if (requestBody == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is not found");
        }

        String format = "";
        if (ocspPrivateKey instanceof RSAPrivateKey) {
            format = "RSA";
        } else if (ocspPrivateKey instanceof ECPrivateKey) {
            format = "ECDSA";
        } else if (ocspPrivateKey instanceof DSAPrivateKey) {
            format = "DSA";
        }

        Date now = LocalDate.now().toDate();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
        BasicOCSPRespBuilder ocspRespBuilder = new JcaBasicOCSPRespBuilder(ocspCertificate.getPublicKey(), digCalcProv.get(RespID.HASH_SHA1));

        OCSPReq ocspReq = new OCSPReq(requestBody);
        for (Req req : ocspReq.getRequestList()) {
            CertificateID certId = req.getCertID();

            CertificateID respCertId = new CertificateID(
                    new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                    new JcaX509CertificateHolder(issuerCertificate.getCertificate()),
                    certId.getSerialNumber()
            );

            Certificate certificate = this.certificateRepository.findBySerial(certId.getSerialNumber().longValueExact());
            if (certificate == null) {
                ocspRespBuilder.addResponse(respCertId, new RevokedStatus(now, CRLReason.certificateHold));
            } else {
                if (certificate.getStatus() == CertificateStatusEnum.Good) {
                    X509Certificate cert = certificate.getCertificate();
                    try {
                        cert.checkValidity();
                        ocspRespBuilder.addResponse(respCertId, CertificateStatus.GOOD);
                    } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                        ocspRespBuilder.addResponse(respCertId, new RevokedStatus(certificate.getRevokedDate(), CRLReason.cessationOfOperation));
                    }
                } else {
                    ocspRespBuilder.addResponse(respCertId, new RevokedStatus(certificate.getRevokedDate(), CRLReason.cessationOfOperation));
                }
            }
        }

        int keySize = 256;
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + keySize + "WITH" + format);
        contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner contentSigner = contentSignerBuilder.build(ocspPrivateKey);

        BasicOCSPResp resp = ocspRespBuilder.build(contentSigner, new X509CertificateHolder[]{new JcaX509CertificateHolder(ocspCertificate)}, now);
        OCSPRespBuilder respBuilder = new OCSPRespBuilder();
        OCSPResp ocspResp = respBuilder.build(OCSPRespBuilder.SUCCESSFUL, resp);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "inline");
        headers.add("Content-Type", "application/ocsp-response");
        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(ocspResp.getEncoded());
    }

}
