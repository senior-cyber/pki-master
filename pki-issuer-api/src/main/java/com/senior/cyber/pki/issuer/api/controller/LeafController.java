package com.senior.cyber.pki.issuer.api.controller;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.CertificateService;
import com.senior.cyber.pki.service.UserService;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;
import org.joda.time.LocalDate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Date;

@RestController
public class LeafController {

    private static final Logger LOGGER = LoggerFactory.getLogger(LeafController.class);

    @Autowired
    protected CertificateService certificateService;

    @Value("${api.crl}")
    protected String crlApi;

    @Value("${api.ocsp}")
    protected String ocspApi;

    @Value("${api.x509}")
    protected String x509Api;

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Autowired
    protected UserService userService;

    @RequestMapping(path = "/server/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ServerGenerateResponse> serverGenerate(RequestEntity<ServerGenerateRequest> httpRequest) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, BadResponseException, ApduException, ApplicationNotAvailableException {
        ServerGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Date now = LocalDate.now().toDate();
        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerCertificateId()).orElseThrow();
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Intermediate &&
                        issuerCertificate.getType() != CertificateTypeEnum.Root) ||
                issuerCertificate.getValidFrom().after(now) ||
                issuerCertificate.getValidUntil().before(now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerCertificateId() + " is not valid");
        }
        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElse(null);
        if (issuerKey == null) {
            throw new IllegalArgumentException("issuerKey not found");
        }

        String serial = String.format("%012X", issuerCertificate.getSerial());

        ServerGenerateResponse response = this.certificateService.serverGenerate(request, this.crlApi + "/" + serial + ".crl", this.ocspApi + "/" + serial, this.x509Api + "/" + serial + ".der");
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/mtls/client/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<MtlsClientGenerateResponse> mtlsClientGenerate(RequestEntity<MtlsClientGenerateRequest> httpRequest) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, BadResponseException, ApduException, ApplicationNotAvailableException {
        MtlsClientGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Date now = LocalDate.now().toDate();
        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerCertificateId()).orElseThrow();
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.MutualTLS) ||
                issuerCertificate.getValidFrom().after(now) ||
                issuerCertificate.getValidUntil().before(now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerCertificateId() + " is not valid");
        }
        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElse(null);
        if (issuerKey == null) {
            throw new IllegalArgumentException("issuerKey not found");
        }

        String serial = String.format("%012X", issuerCertificate.getSerial());

        MtlsClientGenerateResponse response = this.certificateService.mtlsClientGenerate(request, this.crlApi + "/" + serial + ".crl", this.ocspApi + "/" + serial, this.x509Api + "/" + serial + ".der");
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/ssh/client/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SshClientGenerateResponse> sshClientGenerate(RequestEntity<SshClientGenerateRequest> httpRequest) throws Exception {
        SshClientGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Key issuerKey = this.keyRepository.findById(request.getIssuerKeyId()).orElseThrow();

        switch (issuerKey.getUsage()) {
            case SSH -> {
                SshClientGenerateResponse response = this.certificateService.sshClientGenerate(request);
                return ResponseEntity.ok(response);
            }
            default -> {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerKeyId() + " is not found");
            }
        }
    }

}
