package com.senior.cyber.pki.root.api.controller;

import com.senior.cyber.pki.common.dto.JcaRootGenerateRequest;
import com.senior.cyber.pki.common.dto.JcaRootGenerateResponse;
import com.senior.cyber.pki.common.dto.YubicoRootGenerateRequest;
import com.senior.cyber.pki.common.dto.YubicoRootGenerateResponse;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.service.RootService;
import com.senior.cyber.pki.service.UserService;
import com.yubico.yubikit.piv.Slot;
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

    @RequestMapping(path = "/root/jca/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JcaRootGenerateResponse> jcaRootGenerate(RequestEntity<JcaRootGenerateRequest> httpRequest) {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        JcaRootGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        JcaRootGenerateResponse response = this.rootService.rootGenerate(user, request);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/root/yubico/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<YubicoRootGenerateResponse> yubicoRootGenerate(RequestEntity<YubicoRootGenerateRequest> httpRequest) {
        User user = this.userService.authenticate(httpRequest.getHeaders().getFirst("Authorization"));
        YubicoRootGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        if (request.getSerialNumber() == null || request.getSerialNumber().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Slot pivSlot = null;
        if (request.getSlot() == null || request.getSlot().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        } else {
            for (Slot slot : Slot.values()) {
                if (slot.getStringAlias().equalsIgnoreCase(request.getSlot())) {
                    pivSlot = slot;
                    break;
                }
            }
            request.setSlot(null);
        }
        if (pivSlot == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        if (request.getPin() == null || request.getPin().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        if (request.getManagementKey() == null || request.getManagementKey().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        YubicoRootGenerateResponse response = this.rootService.rootGenerate(user, request, pivSlot);
        return ResponseEntity.ok(response);
    }

}
