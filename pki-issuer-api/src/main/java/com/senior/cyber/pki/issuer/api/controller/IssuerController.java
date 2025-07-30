package com.senior.cyber.pki.issuer.api.controller;

import com.senior.cyber.pki.common.dto.JcaIssuerGenerateRequest;
import com.senior.cyber.pki.common.dto.JcaIssuerGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoIssuerGenerateRequest;
import com.senior.cyber.pki.common.dto.YubicoIssuerGenerateResponse;
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
import com.yubico.yubikit.piv.Slot;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.openssl.PEMException;
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
public class IssuerController {

    private static final Logger LOGGER = LoggerFactory.getLogger(IssuerController.class);

    @Autowired
    protected IssuerService issuerService;

    @Value("${api.crl}")
    protected String crlApi;

    @Value("${api.ocsp}")
    protected String ocspApi;

    @Value("${api.x509}")
    protected String x509Api;

    @Value("${api.ssh}")
    protected String sshApi;

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Autowired
    protected UserService userService;

    @RequestMapping(path = "/issuer/jca/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JcaIssuerGenerateResponse> jcaIssuerGenerate(RequestEntity<JcaIssuerGenerateRequest> httpRequest) throws PEMException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
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

        JcaIssuerGenerateResponse response = this.issuerService.issuerGenerate(user, request, this.crlApi, this.ocspApi, this.x509Api, this.sshApi, issuerPivSlot);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/issuer/yubico/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<YubicoIssuerGenerateResponse> yubicoIssuerGenerate(RequestEntity<YubicoIssuerGenerateRequest> httpRequest) {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        YubicoIssuerGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if (request.getSerialNumber() == null || request.getSerialNumber().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        Slot pivSlot = null;
        if (request.getSlot() == null || request.getSlot().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        } else {
            for (Slot slot : Slot.values()) {
                if (slot.getStringAlias().equalsIgnoreCase(request.getSlot())) {
                    pivSlot = slot;
                    break;
                }
            }
            request.setSlot(null);
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

        YubicoIssuerGenerateResponse response = this.issuerService.issuerGenerate(user, request, this.crlApi, this.ocspApi, this.x509Api, this.sshApi, issuerPivSlot, pivSlot);
        return ResponseEntity.ok(response);
    }

}
