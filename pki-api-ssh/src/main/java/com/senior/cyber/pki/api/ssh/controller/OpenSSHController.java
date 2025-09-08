package com.senior.cyber.pki.api.ssh.controller;

import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import org.apache.commons.io.FilenameUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

@RestController
public class OpenSSHController {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenSSHController.class);

    @Autowired
    protected KeyRepository keyRepository;

    @Autowired
    protected CertificateRepository certificateRepository;

    @RequestMapping(path = "/openssh/{serial:.+}", method = RequestMethod.GET, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> opensshSerial(RequestEntity<Void> httpRequest, @PathVariable("serial") String serial) throws IOException {
        LOGGER.info("PathInfo [{}] UserAgent [{}]", httpRequest.getUrl(), httpRequest.getHeaders().getFirst("User-Agent"));
        if (!"pub".equals(FilenameUtils.getExtension(serial))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is invalid");
        }

        Key key = this.keyRepository.findById(serial).orElseThrow();

        switch (key.getKeyFormat()) {
            case RSA -> {
                switch (key.getUsage()) {
                    case SSH -> {
                        return ResponseEntity.ok(PublicKeyEntry.toString(key.getPublicKey()));
                    }
                    default -> {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is not found");
                    }
                }
            }
            default -> {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is not found");
            }
        }
    }

}
