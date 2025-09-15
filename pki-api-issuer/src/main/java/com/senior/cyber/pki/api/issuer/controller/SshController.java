package com.senior.cyber.pki.api.issuer.controller;

import com.senior.cyber.pki.common.dto.SshClientGenerateRequest;
import com.senior.cyber.pki.common.dto.SshClientGenerateResponse;
import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.SshCAService;
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

@RestController
public class SshController {

    private static final Logger LOGGER = LoggerFactory.getLogger(SshController.class);

    @Autowired
    protected SshCAService sshcaService;

    @Autowired
    protected KeyRepository keyRepository;

    @RequestMapping(path = "/ssh/client/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SshClientGenerateResponse> sshClientGenerate(RequestEntity<SshClientGenerateRequest> httpRequest) throws Exception {
        SshClientGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Key issuerKey = this.keyRepository.findById(request.getIssuer().getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "issuer key is not found"));
        if (issuerKey.getStatus() == KeyStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "issuer key have been revoked");
        }

        if (issuerKey.getKeyFormat() == KeyFormatEnum.RSA) {
            SshClientGenerateResponse response = this.sshcaService.sshClientGenerate(request);
            return ResponseEntity.ok(response);
        } else {
            LOGGER.info("issuer key format type is {}", issuerKey.getType());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "issuer key format is not type of [" + KeyFormatEnum.RSA.name() + "]");
        }
    }

}
