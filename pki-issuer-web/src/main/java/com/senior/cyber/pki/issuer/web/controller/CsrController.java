package com.senior.cyber.pki.issuer.web.controller;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping(path = "/csr")
@RequiredArgsConstructor
public class CsrController {

    private static final Logger LOGGER = LoggerFactory.getLogger(CsrController.class);

    @RequestMapping(path = {"/generate"}, method = RequestMethod.GET)
    public String generateGet(Model model) {
        return "user/user-browse";
    }

}
