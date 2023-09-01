package com.senior.cyber.pki.client.web.controller;

import jakarta.persistence.Enumerated;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Enumeration;

@RestController
public class WebController {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebController.class);

    @RequestMapping(path = "/")
    public ResponseEntity<String> x509Serial(RequestEntity<Void> httpRequest, HttpServletRequest request) {
        Enumeration<String> names = request.getAttributeNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            LOGGER.info("{} : {}", name, request.getAttribute(name));
        }
        return ResponseEntity.ok(httpRequest.getUrl().toString());
    }

}
