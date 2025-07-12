package com.senior.cyber.pki.root.api.controller;

import com.senior.cyber.pki.common.dto.RootGenerateRequest;
import com.senior.cyber.pki.common.dto.RootGenerateResponse;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.service.RootService;
import com.senior.cyber.pki.service.UserService;
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

@RestController
public class RootController {

    private static final Logger LOGGER = LoggerFactory.getLogger(RootController.class);

    @Autowired
    protected RootService rootService;

    @Autowired
    protected UserService userService;

    @RequestMapping(path = "/root/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<RootGenerateResponse> rootGenerate(RequestEntity<RootGenerateRequest> httpRequest) {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        RootGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        RootGenerateResponse response = this.rootService.rootGenerate(user, request);
        return ResponseEntity.ok(response);
    }

}
