package com.senior.cyber.pki.api.issuer.controller;

import com.senior.cyber.pki.common.dto.SshGenerateRequest;
import com.senior.cyber.pki.common.dto.SshGenerateResponse;
import com.senior.cyber.pki.common.x509.KeyFormat;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.SshCAService;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@RestController
public class SshController {

    private static final Logger LOGGER = LoggerFactory.getLogger(SshController.class);

    @Autowired
    protected SshCAService sshcaService;

    @Autowired
    protected KeyRepository keyRepository;

    @RequestMapping(path = "/ssh/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SshGenerateResponse> rootGenerate(RequestEntity<SshGenerateRequest> httpRequest) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        SshGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not found"));
        if (key.getStatus() == KeyStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key have been revoked");
        }

        if (key.getKeyFormat() != KeyFormat.RSA) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key format is not supported");
        }

        SshGenerateResponse response = this.sshcaService.sshcaGenerate(request);
        return ResponseEntity.ok(response);
    }

}
