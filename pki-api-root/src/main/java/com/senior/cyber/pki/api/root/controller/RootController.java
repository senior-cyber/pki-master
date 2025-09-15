package com.senior.cyber.pki.api.root.controller;

import com.senior.cyber.pki.common.dto.RootClientRegisterRequest;
import com.senior.cyber.pki.common.dto.RootServerGenerateRequest;
import com.senior.cyber.pki.common.dto.RootServerGenerateResponse;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.RootService;
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
public class RootController {

    private static final Logger LOGGER = LoggerFactory.getLogger(RootController.class);

    @Autowired
    protected RootService rootService;

    @Autowired
    protected KeyRepository keyRepository;

    /**
     * for issue self sign root ca
     *
     * @param httpRequest
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     * @throws IOException
     * @throws ApduException
     * @throws ApplicationNotAvailableException
     * @throws BadResponseException
     */
    @RequestMapping(path = "/root/server/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<RootServerGenerateResponse> rootServerGenerate(RequestEntity<RootServerGenerateRequest> httpRequest) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        RootServerGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not found"));
        if (key.getStatus() == KeyStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key have been revoked");
        }

        RootServerGenerateResponse response = this.rootService.rootServerGenerate(request);
        return ResponseEntity.ok(response);
    }

    /**
     * for issue self sign root ca
     *
     * @param httpRequest
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     * @throws IOException
     * @throws ApduException
     * @throws ApplicationNotAvailableException
     * @throws BadResponseException
     */
    @RequestMapping(path = "/root/client/register", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<RootServerGenerateResponse> rootClientRegister(RequestEntity<RootClientRegisterRequest> httpRequest) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, ApduException, ApplicationNotAvailableException, BadResponseException {
        RootClientRegisterRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not found"));
        if (key.getStatus() == KeyStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key have been revoked");
        }

        RootServerGenerateResponse response = this.rootService.rootClientRegister(null, null, null, request);
        return ResponseEntity.ok(response);
    }

}
