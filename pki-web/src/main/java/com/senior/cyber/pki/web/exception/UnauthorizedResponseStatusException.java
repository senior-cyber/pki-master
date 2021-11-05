package com.senior.cyber.pki.web.exception;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class UnauthorizedResponseStatusException extends ResponseStatusException {

    private String realm;

    public UnauthorizedResponseStatusException(String realm) {
        super(HttpStatus.UNAUTHORIZED);
        this.realm = realm;
    }

    @Override
    public HttpHeaders getResponseHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
        return headers;
    }

}
