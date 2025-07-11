package com.senior.cyber.pki.issuer.api.controller;

import com.senior.cyber.pki.common.dto.CertificateCommonGenerateRequest;
import com.senior.cyber.pki.common.dto.CertificateCommonGenerateResponse;
import com.senior.cyber.pki.common.dto.CertificateTlsGenerateRequest;
import com.senior.cyber.pki.common.dto.CertificateTlsGenerateResponse;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.service.CertificateService;
import com.senior.cyber.pki.service.UserService;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
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
public class CertificateController {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateController.class);

    @Autowired
    protected CertificateService certificateService;

    @Value("${api.crl}")
    protected String crlApi;

    @Value("${api.aia}")
    protected String aiaApi;

    @Autowired
    protected UserService userService;

    @RequestMapping(path = "/certificate/common/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CertificateCommonGenerateResponse> certificateCommonGenerate(RequestEntity<CertificateCommonGenerateRequest> httpRequest) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException, PKCSException {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        CertificateCommonGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        CertificateCommonGenerateResponse response = this.certificateService.certificateCommonGenerate(user, request, this.crlApi, this.aiaApi);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/certificate/tls/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CertificateTlsGenerateResponse> certificateTlsGenerate(RequestEntity<CertificateTlsGenerateRequest> httpRequest) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException, PKCSException {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        CertificateTlsGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        CertificateTlsGenerateResponse response = this.certificateService.certificateTlsGenerate(user, request, this.crlApi, this.aiaApi);
        return ResponseEntity.ok(response);
    }

}
