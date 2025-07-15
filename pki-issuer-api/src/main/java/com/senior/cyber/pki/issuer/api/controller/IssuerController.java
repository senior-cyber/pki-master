package com.senior.cyber.pki.issuer.api.controller;

import com.senior.cyber.pki.common.dto.JcaIssuerGenerateRequest;
import com.senior.cyber.pki.common.dto.JcaIssuerGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoIssuerGenerateRequest;
import com.senior.cyber.pki.common.dto.YubicoIssuerGenerateResponse;
import com.senior.cyber.pki.common.x509.YubicoPivSlotEnum;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.IssuerService;
import com.senior.cyber.pki.service.UserService;
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

import java.util.Date;

@RestController
public class IssuerController {

    private static final Logger LOGGER = LoggerFactory.getLogger(IssuerController.class);

    @Autowired
    protected IssuerService issuerService;

    @Autowired
    protected CertificateRepository certificateRepository;

    @Value("${api.crl}")
    protected String crlApi;

    @Value("${api.ocsp}")
    protected String ocspApi;

    @Value("${api.x509}")
    protected String x509Api;

    @Autowired
    protected KeyRepository keyRepository;

    @Autowired
    protected UserService userService;

    @Transactional(rollbackFor = Throwable.class)
    @RequestMapping(path = "/issuer/jca/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JcaIssuerGenerateResponse> jcaIssuerGenerate(RequestEntity<JcaIssuerGenerateRequest> httpRequest) {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        JcaIssuerGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        Date now = LocalDate.now().toDate();
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Issuer && issuerCertificate.getType() != CertificateTypeEnum.Root) ||
                issuerCertificate.getValidFrom().after(now) ||
                issuerCertificate.getValidUntil().before(now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
        }
        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElse(null);
        if (issuerKey == null) {
            throw new IllegalArgumentException("issuerKey not found");
        }

        YubicoPivSlotEnum issuerPivSlot = null;
        if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            if (request.getIssuerUsbSlot() == null || request.getIssuerUsbSlot().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
            if (request.getIssuerPivSlot() == null || request.getIssuerPivSlot().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            } else {
                for (YubicoPivSlotEnum slot : YubicoPivSlotEnum.values()) {
                    if (slot.getSlotName().equalsIgnoreCase(request.getIssuerPivSlot())) {
                        issuerPivSlot = slot;
                        break;
                    }
                }
                request.setIssuerPivSlot(null);
            }
            if (issuerPivSlot == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
            if (request.getIssuerPin() == null || request.getIssuerPin().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        }

        JcaIssuerGenerateResponse response = this.issuerService.issuerGenerate(user, request, this.crlApi, this.ocspApi, this.x509Api, issuerPivSlot);
        return ResponseEntity.ok(response);
    }

    @Transactional(rollbackFor = Throwable.class)
    @RequestMapping(path = "/issuer/yubico/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<YubicoIssuerGenerateResponse> yubicoIssuerGenerate(RequestEntity<YubicoIssuerGenerateRequest> httpRequest) {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        YubicoIssuerGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getUsbSlot() == null || request.getUsbSlot().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        YubicoPivSlotEnum pivSlot = null;
        if (request.getPivSlot() == null || request.getPivSlot().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        } else {
            for (YubicoPivSlotEnum slot : YubicoPivSlotEnum.values()) {
                if (slot.getSlotName().equalsIgnoreCase(request.getPivSlot())) {
                    pivSlot = slot;
                    break;
                }
            }
            request.setPivSlot(null);
        }
        if (pivSlot == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        if (request.getPin() == null || request.getPin().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        if (request.getManagementKey() == null || request.getManagementKey().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerId()).orElse(null);
        if (issuerCertificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not found");
        }
        Date now = LocalDate.now().toDate();
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.Issuer && issuerCertificate.getType() != CertificateTypeEnum.Root) ||
                issuerCertificate.getValidFrom().after(now) ||
                issuerCertificate.getValidUntil().before(now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuerId() + " is not valid");
        }
        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElse(null);
        if (issuerKey == null) {
            throw new IllegalArgumentException("issuerKey not found");
        }

        YubicoPivSlotEnum issuerPivSlot = null;
        if (issuerKey.getType() == KeyTypeEnum.ServerKeyYubico) {
            if (request.getIssuerUsbSlot() == null || request.getIssuerUsbSlot().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
            if (request.getIssuerPivSlot() == null || request.getIssuerPivSlot().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            } else {
                for (YubicoPivSlotEnum slot : YubicoPivSlotEnum.values()) {
                    if (slot.getSlotName().equalsIgnoreCase(request.getIssuerPivSlot())) {
                        issuerPivSlot = slot;
                        break;
                    }
                }
                request.setIssuerPivSlot(null);
            }
            if (issuerPivSlot == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
            if (request.getIssuerPin() == null || request.getIssuerPin().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        }

        YubicoIssuerGenerateResponse response = this.issuerService.issuerGenerate(user, request, this.crlApi, this.ocspApi, this.x509Api, issuerPivSlot, pivSlot);
        return ResponseEntity.ok(response);
    }

}
