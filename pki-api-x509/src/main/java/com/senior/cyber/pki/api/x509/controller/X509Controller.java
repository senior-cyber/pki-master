package com.senior.cyber.pki.api.x509.controller;

import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.security.cert.CertificateException;

@RestController
public class X509Controller {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509Controller.class);

    @Autowired
    protected CertificateRepository certificateRepository;

    @RequestMapping(path = "/x509/{serial:.+}", method = RequestMethod.GET, produces = "application/pkix-cert")
    public ResponseEntity<byte[]> x509Serial(RequestEntity<Void> httpRequest, @PathVariable("serial") String _serial) throws CertificateException {
        LOGGER.info("PathInfo [{}] UserAgent [{}]", httpRequest.getUrl(), httpRequest.getHeaders().getFirst("User-Agent"));
        long serial = -1;
        try {
            serial = Long.parseLong(FilenameUtils.getBaseName(_serial), 16);
        } catch (NumberFormatException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is invalid");
        }
        Certificate certificate = certificateRepository.findBySerial(serial);
        if (certificate == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, serial + " is not found");
        }
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "inline");
        headers.add("Content-Type", "application/pkix-cert");
        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(certificate.getCertificate().getEncoded());
    }

}
