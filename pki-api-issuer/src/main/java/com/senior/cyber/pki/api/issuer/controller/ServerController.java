package com.senior.cyber.pki.api.issuer.controller;

import com.senior.cyber.pki.common.dto.ServerInfoResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ServerController {

    @Value("${api.crl}")
    protected String apiCrl;

    @Value("${api.ocsp}")
    protected String apiOcsp;

    @Value("${api.x509}")
    protected String apiX509;

    @RequestMapping(path = "/server/info", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ServerInfoResponse> serverInfo(RequestEntity<Void> httpRequest) {
        ServerInfoResponse response = new ServerInfoResponse(this.apiCrl, this.apiOcsp, this.apiX509);
        return ResponseEntity.ok(response);
    }

}
