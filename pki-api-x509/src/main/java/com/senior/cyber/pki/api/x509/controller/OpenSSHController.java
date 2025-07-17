package com.senior.cyber.pki.api.x509.controller;

import com.senior.cyber.pki.common.x509.PublicKeyUtils;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

@RestController
public class OpenSSHController {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenSSHController.class);

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @RequestMapping(path = "/openssl/{serial:.+}", method = RequestMethod.GET, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> x509Serial(RequestEntity<Void> httpRequest, @PathVariable("serial") String _serial) throws CertificateException {
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

        File work = new File(FileUtils.getTempDirectory(), FilenameUtils.getBaseName(_serial));
        work.mkdirs();

        try {
            File publicKeyFile = new File(work, "public.pem");
            File opensshPublicKeyFile = new File(work, "public-openssh.pub");
            FileUtils.write(publicKeyFile, PublicKeyUtils.convert(key.getPublicKey()), StandardCharsets.UTF_8);
            List<String> lines = new ArrayList<>();
            lines.add("#!/usr/bin/env bash");
            lines.add("");
            lines.add("ssh-keygen -f " + publicKeyFile.getAbsolutePath() + " -i -m PKCS8 > " + opensshPublicKeyFile.getAbsolutePath());
            File scriptFile = new File(work, "convert.sh");
            FileUtils.writeLines(scriptFile, StandardCharsets.UTF_8.name(), lines);
            DefaultExecutor executor = DefaultExecutor.builder().get();
            CommandLine cli = CommandLine.parse("sh " + scriptFile.getAbsolutePath());
            executor.execute(cli);
            String opensshPublicKey = FileUtils.readFileToString(opensshPublicKeyFile, StandardCharsets.UTF_8);
            return ResponseEntity.ok(opensshPublicKey);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            FileUtils.deleteQuietly(work);
        }
    }

}
