package com.senior.cyber.pki.api.ssh.controller;

import com.senior.cyber.pki.dao.entity.pki.Certificate;
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
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @RequestMapping(path = "/openssh/{serial:.+}", method = RequestMethod.GET, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> opensshSerial(RequestEntity<Void> httpRequest, @PathVariable("serial") String _serial) throws IOException {
        LOGGER.info("PathInfo [{}] UserAgent [{}]", httpRequest.getUrl(), httpRequest.getHeaders().getFirst("User-Agent"));
        if (!"pub".equals(FilenameUtils.getExtension(_serial))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, _serial + " is invalid");
        }

        long serial = -1;
        try {
            serial = Long.parseLong(FilenameUtils.getBaseName(_serial), 16);
        } catch (NumberFormatException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is invalid");
        }
        Certificate certificate = this.certificateRepository.findBySerial(serial);
        if (certificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is not found");
        }

        Key key = this.keyRepository.findById(certificate.getKey().getId()).orElse(null);
        if (key == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is not found");
        }

        return ResponseEntity.ok(PublicKeyEntry.toString(key.getPublicKey()));
    }

}
