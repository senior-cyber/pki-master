package com.senior.cyber.pki.api.ssh.controller;

import com.senior.cyber.pki.common.x509.KeyFormat;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
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
import java.util.Date;

@RestController
public class OpenSSHController {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenSSHController.class);

    @Autowired
    protected KeyRepository keyRepository;

    @RequestMapping(path = "/openssh/{serial:.+}", method = RequestMethod.GET, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> opensshSerial(HttpServletRequest request, RequestEntity<Void> httpRequest, @PathVariable("serial") String serial) throws IOException {
        String remoteAddress = request.getRemoteAddr();
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            String[] temp = StringUtils.split(xForwardedFor, ",");
            remoteAddress = StringUtils.trim(temp[0]);
        }
        Date now = new Date();
        LOGGER.info("[{}] [{}] PathInfo [{}] UserAgent [{}]", DateFormatUtils.ISO_8601_EXTENDED_DATETIME_TIME_ZONE_FORMAT.format(now), remoteAddress, httpRequest.getUrl(), httpRequest.getHeaders().getFirst("User-Agent"));

        String keyId = FilenameUtils.getBaseName(serial);
        Key key = this.keyRepository.findById(keyId).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not found"));
        if (key.getStatus() == KeyStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key have been revoked");
        }

        if (!"pub".equalsIgnoreCase(FilenameUtils.getExtension(serial))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not found");
        }

        if (key.getKeyFormat() == KeyFormat.RSA) {
            return ResponseEntity.ok(PublicKeyEntry.toString(key.getPublicKey()));
        } else {
            LOGGER.info("key format is {}", key.getKeyFormat());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key format is not type of [" + KeyFormat.RSA + "]");
        }
    }

}
