package com.senior.cyber.pki.root.api.controller;

import com.senior.cyber.pki.common.dto.IssuerGenerateRequest;
import com.senior.cyber.pki.common.dto.IssuerGenerateResponse;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.service.IssuerService;
import com.senior.cyber.pki.service.UserService;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

@RestController
public class IssuerController {

    private static final Logger LOGGER = LoggerFactory.getLogger(IssuerController.class);

    @Autowired
    protected IssuerService issuerService;

    @Autowired
    protected CertificateRepository certificateRepository;

    @Value("${api.crl}")
    protected String crlApi;

    @Value("${api.aia}")
    protected String aiaApi;

    @Autowired
    protected UserService userService;

    @RequestMapping(path = "/issuer/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<IssuerGenerateResponse> issuerGenerate(RequestEntity<IssuerGenerateRequest> httpRequest) throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException, PKCSException {
        User user = userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        IssuerGenerateRequest request = httpRequest.getBody();
        IssuerGenerateResponse response = issuerService.issuerGenerate(user, request, crlApi, aiaApi);
        return ResponseEntity.ok(response);
    }

}
