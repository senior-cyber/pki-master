package com.senior.cyber.pki.api.issuer.controller;

import com.senior.cyber.pki.common.dto.SshGenerateRequest;
import com.senior.cyber.pki.common.dto.SshGenerateResponse;
import com.senior.cyber.pki.service.SshCAService;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.operator.OperatorCreationException;
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

@RestController
public class SshController {

    private static final Logger LOGGER = LoggerFactory.getLogger(SshController.class);

    @Value("${api.crl}")
    protected String crlApi;

    @Value("${api.ocsp}")
    protected String ocspApi;

    @Value("${api.x509}")
    protected String x509Api;

    @Value("${api.ssh}")
    protected String sshApi;

    @Autowired
    protected SshCAService sshcaService;

    @RequestMapping(path = "/ssh/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SshGenerateResponse> rootGenerate(RequestEntity<SshGenerateRequest> httpRequest) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        SshGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        switch (request.getSize()) {
            case 1024, 2048 -> {
                SshGenerateResponse response = this.sshcaService.sshcaGenerate(request, this.sshApi);
                return ResponseEntity.ok(response);
            }
            default -> {
                LOGGER.info("invalid size {}", request.getSize());
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "size is not one of 1024, 2048");
            }
        }
    }

}
