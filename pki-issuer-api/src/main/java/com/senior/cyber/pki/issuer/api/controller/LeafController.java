package com.senior.cyber.pki.issuer.api.controller;

import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
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

    @RequestMapping(path = "/leaf/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<LeafGenerateResponse> leafGenerate(RequestEntity<LeafGenerateRequest> httpRequest) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, BadResponseException, ApduException, ApplicationNotAvailableException {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));

        LeafGenerateRequest request = httpRequest.getBody();
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

        LeafGenerateResponse response = this.certificateService.leafGenerate(user, request, this.crlApi, this.ocspApi, this.x509Api);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/server/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<LeafGenerateResponse> serverGenerate(RequestEntity<ServerCertificateGenerateRequest> httpRequest) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, BadResponseException, ApduException, ApplicationNotAvailableException {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        ServerCertificateGenerateRequest request = httpRequest.getBody();
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

        LeafGenerateResponse response = this.certificateService.serverGenerate(user, request, this.crlApi, this.ocspApi, this.x509Api);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/client/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<LeafGenerateResponse> clientGenerate(RequestEntity<LeafGenerateRequest> httpRequest) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, BadResponseException, ApduException, ApplicationNotAvailableException {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        LeafGenerateRequest request = httpRequest.getBody();
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

        LeafGenerateResponse response = this.certificateService.clientGenerate(user, request, this.crlApi, this.ocspApi, this.x509Api);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/ssh/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SshCertificateGenerateResponse> sshGenerate(RequestEntity<SshCertificateGenerateRequest> httpRequest) {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        SshCertificateGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Date now = LocalDate.now().toDate();
        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Intermediate &&
                        issuerCertificate.getType() != CertificateTypeEnum.Root) ||
                issuerCertificate.getValidFrom().after(now) ||
                issuerCertificate.getValidUntil().before(now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
        }
        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElse(null);
        if (issuerKey == null) {
            throw new IllegalArgumentException("issuerKey not found");
        }

        if (issuerKey.getType() != KeyTypeEnum.ServerKeyJCE) {
            throw new IllegalArgumentException("issuerKey not found");
        }

        SshCertificateGenerateResponse response = this.certificateService.sshGenerate(user, request);
        return ResponseEntity.ok(response);
    }

}
