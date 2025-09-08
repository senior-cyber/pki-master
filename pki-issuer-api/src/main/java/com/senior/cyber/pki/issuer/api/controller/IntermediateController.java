package com.senior.cyber.pki.issuer.api.controller;

import com.senior.cyber.pki.common.dto.IntermediateGenerateRequest;
import com.senior.cyber.pki.common.dto.IntermediateGenerateResponse;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.IntermediateService;
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
public class IntermediateController {

    private static final Logger LOGGER = LoggerFactory.getLogger(IntermediateController.class);

    @Autowired
    protected IntermediateService intermediateService;

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

    @RequestMapping(path = "/intermediate/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<IntermediateGenerateResponse> intermediateGenerate(RequestEntity<IntermediateGenerateRequest> httpRequest) throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, ApduException, ApplicationNotAvailableException, BadResponseException {
        IntermediateGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuer().getCertificateId()).orElseThrow();
        Date now = LocalDate.now().toDate();
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked ||
                (issuerCertificate.getType() != CertificateTypeEnum.INTERMEDIATE && issuerCertificate.getType() != CertificateTypeEnum.ROOT) ||
                issuerCertificate.getValidFrom().after(now) ||
                issuerCertificate.getValidUntil().before(now)
        ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, request.getIssuer().getCertificateId() + " is not valid");
        }

        Key certKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElseThrow();
        if (certKey.getStatus() == KeyStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow();
        if (key.getStatus() == KeyStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        String serial = String.format("%012X", issuerCertificate.getSerial());

        IntermediateGenerateResponse response = this.intermediateService.intermediateGenerate(request, this.crlApi + "/" + serial + ".crl", this.ocspApi + "/" + serial, this.x509Api + "/" + serial + ".der");
        return ResponseEntity.ok(response);
    }

}
