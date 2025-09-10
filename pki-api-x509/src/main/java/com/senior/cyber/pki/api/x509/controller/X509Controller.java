package com.senior.cyber.pki.api.x509.controller;

import com.senior.cyber.pki.common.x509.CertificateUtils;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.util.Date;

@RestController
public class X509Controller {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509Controller.class);

    @Autowired
    protected CertificateRepository certificateRepository;

    @RequestMapping(path = "/x509/{serial:.+}", method = RequestMethod.GET)
    public ResponseEntity<byte[]> x509Serial(HttpServletRequest request, RequestEntity<Void> httpRequest, @PathVariable("serial") String _serial) throws CertificateException {
        String remoteAddress = request.getRemoteAddr();
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            String[] temp = StringUtils.split(xForwardedFor, ",");
            remoteAddress = StringUtils.trim(temp[0]);
        }
        Date now = new Date();
        LOGGER.info("[{}] [{}] PathInfo [{}] UserAgent [{}]", DateFormatUtils.ISO_8601_EXTENDED_DATETIME_TIME_ZONE_FORMAT.format(now), remoteAddress, httpRequest.getUrl(), httpRequest.getHeaders().getFirst("User-Agent"));

        String extension = StringUtils.lowerCase(FilenameUtils.getExtension(_serial));
        switch (extension) {
            case "der" -> {
                long serial = -1;
                try {
                    serial = Long.parseLong(FilenameUtils.getBaseName(_serial), 16);
                } catch (NumberFormatException e) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "serial is invalid");
                }
                Certificate certificate = this.certificateRepository.findBySerial(serial);
                if (certificate == null) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "certificate is not found");
                }
                if (certificate.getStatus() == CertificateStatusEnum.Revoked) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "certificate have been revoked");
                }
                switch (certificate.getType()) {
                    case ROOT_CA, SUBORDINATE_CA, ISSUING_CA -> {
                        HttpHeaders headers = new HttpHeaders();
                        headers.add("Content-Disposition", "inline");
                        headers.add("Content-Type", "application/pkix-cert");
                        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(certificate.getCertificate().getEncoded());
                    }
                    default -> {
                        LOGGER.info("certificate type is {}", certificate.getType());
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "certificate type is not type of [" + CertificateTypeEnum.ROOT_CA + ", " + CertificateTypeEnum.SUBORDINATE_CA + ", " + CertificateTypeEnum.ISSUING_CA + "]");
                    }
                }
            }
            case "crt", "pem" -> {
                long serial = -1;
                try {
                    serial = Long.parseLong(FilenameUtils.getBaseName(_serial), 16);
                } catch (NumberFormatException e) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "serial is invalid");
                }
                Certificate certificate = this.certificateRepository.findBySerial(serial);
                if (certificate == null) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "certificate is not found");
                }
                if (certificate.getStatus() == CertificateStatusEnum.Revoked) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "certificate have been revoked");
                }
                switch (certificate.getType()) {
                    case ROOT_CA, mTLS_SERVER -> {
                        HttpHeaders headers = new HttpHeaders();
                        headers.add("Content-Disposition", "inline");
                        headers.add("Content-Type", MediaType.TEXT_PLAIN_VALUE);
                        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(CertificateUtils.convert(certificate.getCertificate()).getBytes(StandardCharsets.UTF_8));
                    }
                    default -> {
                        LOGGER.info("certificate type is {}", certificate.getType());
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "certificate type is not type of [" + CertificateTypeEnum.ROOT_CA + ", " + CertificateTypeEnum.mTLS_SERVER + "]");
                    }
                }
            }
            default -> {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "type is not type of [der,crt,pem]");
            }
        }
    }

}
