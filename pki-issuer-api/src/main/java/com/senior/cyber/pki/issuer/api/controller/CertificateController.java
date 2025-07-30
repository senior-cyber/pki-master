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
import com.yubico.yubikit.piv.Slot;
import org.bouncycastle.cert.CertIOException;
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

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Date;

@RestController
public class CertificateController {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateController.class);

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

    @RequestMapping(path = "/certificate/common/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CertificateCommonGenerateResponse> certificateCommonGenerate(RequestEntity<CertificateCommonGenerateRequest> httpRequest) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        CertificateCommonGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Date now = LocalDate.now().toDate();
        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Issuer &&
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

        Slot issuerPivSlot = null;
        if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            if (request.getIssuerSerialNumber() == null || request.getIssuerSerialNumber().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
            if (request.getIssuerSlot() == null || request.getIssuerSlot().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            } else {
                for (Slot slot : Slot.values()) {
                    if (slot.getStringAlias().equalsIgnoreCase(request.getIssuerSlot())) {
                        issuerPivSlot = slot;
                        break;
                    }
                }
                request.setIssuerSlot(null);
            }
            if (issuerPivSlot == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
            if (request.getIssuerPin() == null || request.getIssuerPin().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        }

        CertificateCommonGenerateResponse response = this.certificateService.certificateCommonGenerate(user, request, this.crlApi, this.ocspApi, this.x509Api, issuerPivSlot);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/certificate/tls/generate/server", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CertificateTlsGenerateResponse> certificateTlsGenerateServer(RequestEntity<CertificateTlsGenerateRequest> httpRequest) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        CertificateTlsGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Date now = LocalDate.now().toDate();
        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Issuer &&
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

        Slot issuerPivSlot = null;
        if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            if (request.getIssuerSerialNumber() == null || request.getIssuerSerialNumber().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
            if (request.getIssuerSlot() == null || request.getIssuerSlot().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            } else {
                for (Slot slot : Slot.values()) {
                    if (slot.getStringAlias().equalsIgnoreCase(request.getIssuerSlot())) {
                        issuerPivSlot = slot;
                        break;
                    }
                }
                request.setIssuerSlot(null);
            }
            if (issuerPivSlot == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
            if (request.getIssuerPin() == null || request.getIssuerPin().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        }

        CertificateTlsGenerateResponse response = this.certificateService.certificateTlsServerGenerate(user, request, this.crlApi, this.ocspApi, this.x509Api, issuerPivSlot);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/certificate/tls/generate/client", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CertificateTlsGenerateResponse> certificateTlsGenerateClient(RequestEntity<CertificateTlsGenerateRequest> httpRequest) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        CertificateTlsGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Date now = LocalDate.now().toDate();
        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Issuer &&
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

        Slot issuerPivSlot = null;
        if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            if (request.getIssuerSerialNumber() == null || request.getIssuerSerialNumber().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
            if (request.getIssuerSlot() == null || request.getIssuerSlot().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            } else {
                for (Slot slot : Slot.values()) {
                    if (slot.getStringAlias().equalsIgnoreCase(request.getIssuerSlot())) {
                        issuerPivSlot = slot;
                        break;
                    }
                }
                request.setIssuerSlot(null);
            }
            if (issuerPivSlot == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
            if (request.getIssuerPin() == null || request.getIssuerPin().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        }

        CertificateTlsGenerateResponse response = this.certificateService.certificateTlsClientGenerate(user, request, this.crlApi, this.ocspApi, this.x509Api, issuerPivSlot);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/certificate/ssh/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CertificateSshGenerateResponse> certificateSshGenerate(RequestEntity<CertificateSshGenerateRequest> httpRequest) {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        CertificateSshGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Date now = LocalDate.now().toDate();
        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Issuer &&
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

        CertificateSshGenerateResponse response = this.certificateService.certificateSshGenerate(user, request);
        return ResponseEntity.ok(response);
    }

}
