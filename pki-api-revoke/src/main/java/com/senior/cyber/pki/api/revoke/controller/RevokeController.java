package com.senior.cyber.pki.api.revoke.controller;

import com.senior.cyber.pki.common.dto.RevokeCertificateRequest;
import com.senior.cyber.pki.common.dto.RevokeCertificateResponse;
import com.senior.cyber.pki.common.dto.RevokeKeyRequest;
import com.senior.cyber.pki.common.dto.RevokeKeyResponse;
import com.senior.cyber.pki.common.x509.PrivateKeyUtils;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@RestController
public class RevokeController {

    private static final Logger LOGGER = LoggerFactory.getLogger(RevokeController.class);

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @RequestMapping(path = "/revoke/certificate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<RevokeCertificateResponse> revokeCertificate(RequestEntity<RevokeCertificateRequest> httpRequest) throws OperatorCreationException {
        RevokeCertificateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        Certificate certificate = this.certificateRepository.findById(request.getCertificateId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "certificate is not found"));
        if (certificate.getStatus() == CertificateStatusEnum.Good) {
            List<Certificate> certificates = new ArrayList<>();
            certificates.add(certificate);
            if (certificate.getType() == CertificateTypeEnum.ROOT_CA || certificate.getType() == CertificateTypeEnum.SUBORDINATE_CA || certificate.getType() == CertificateTypeEnum.ISSUING_CA) {
                certificates.addAll(lookupCertificates(certificate));
            }
            Key key = this.keyRepository.findById(certificate.getKey().getId()).orElseThrow();
            if (key.getPrivateKey() != null && !key.getPrivateKey().isEmpty()) {
                if (PrivateKeyUtils.convert(key.getPrivateKey(), request.getKeyPassword()) == null) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key password is invalid");
                }
                List<Certificate> revoked = new ArrayList<>();
                for (Certificate cert : certificates) {
                    if (cert.getStatus() == CertificateStatusEnum.Good) {
                        cert.setStatus(CertificateStatusEnum.Revoked);
                        cert.setRevokedDate(new Date());
                        revoked.add(cert);
                    }
                }
                this.certificateRepository.saveAll(revoked);
                return ResponseEntity.ok(new RevokeCertificateResponse());
            } else {
                LOGGER.info("key type is {}", key.getType());
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not type of [" + KeyTypeEnum.ServerKeyJCE.name() + "]");
            }
        } else {
            return ResponseEntity.ok(new RevokeCertificateResponse());
        }
    }

    @RequestMapping(path = "/revoke/key", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<RevokeKeyResponse> revokeKey(RequestEntity<RevokeKeyRequest> httpRequest) throws OperatorCreationException {
        RevokeKeyRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not found"));
        if (key.getPrivateKey() == null || key.getPrivateKey().isEmpty()) {
            LOGGER.info("key type is {}", key.getType());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not type of [" + KeyTypeEnum.ServerKeyJCE.name() + "]");
        }
        if (PrivateKeyUtils.convert(key.getPrivateKey(), request.getKeyPassword()) == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key password is invalid");
        }
        if (key.getStatus() == KeyStatusEnum.Good) {
            key.setStatus(KeyStatusEnum.Revoked);
            this.keyRepository.save(key);
            List<Certificate> certificates = new ArrayList<>();
            for (Certificate certificate : this.certificateRepository.findByKey(key)) {
                certificates.add(certificate);
                if (certificate.getType() == CertificateTypeEnum.ROOT_CA || certificate.getType() == CertificateTypeEnum.SUBORDINATE_CA || certificate.getType() == CertificateTypeEnum.ISSUING_CA) {
                    certificates.addAll(lookupCertificates(certificate));
                }
            }
            List<Certificate> revoked = new ArrayList<>();
            for (Certificate cert : certificates) {
                if (cert.getStatus() == CertificateStatusEnum.Good) {
                    cert.setStatus(CertificateStatusEnum.Revoked);
                    cert.setRevokedDate(new Date());
                    revoked.add(cert);
                }
            }
            this.certificateRepository.saveAll(revoked);
            return ResponseEntity.ok(new RevokeKeyResponse());
        } else {
            return ResponseEntity.ok(new RevokeKeyResponse());
        }
    }

    protected List<Certificate> lookupCertificates(Certificate certificate) {
        List<Certificate> certificates = new ArrayList<>();
        List<Certificate> children = this.certificateRepository.findByIssuerCertificate(certificate);
        for (Certificate child : children) {
            certificates.add(child);
            if (child.getType() == CertificateTypeEnum.ROOT_CA || child.getType() == CertificateTypeEnum.SUBORDINATE_CA || child.getType() == CertificateTypeEnum.ISSUING_CA) {
                certificates.addAll(lookupCertificates(child));
            }
        }
        return certificates;
    }

}
