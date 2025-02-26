package com.senior.cyber.pki.issuer.web.controller;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;

@Controller
@RequestMapping(path = "/user")
@SessionAttributes("userCreateInfo")
@RequiredArgsConstructor
public class UserController {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);

    @RequestMapping(path = {"/browse"}, method = RequestMethod.GET)
    public String browseGet(Model model) {
        return "user/user-browse";
    }

    @RequestMapping(path = {"/create/info"}, method = RequestMethod.GET)
    public String createInfoGet(Model model) {
        return "user/user-create-info";
    }

    @RequestMapping(path = {"/create/password"}, method = RequestMethod.GET)
    public String createPasswordGet(Model model) {
        return "user/user-create-password";
    }

    @RequestMapping(path = {"/modify/info"}, method = RequestMethod.GET)
    public String modifyInfoGet(Model model) {
        return "user/user-browse";
    }

    @RequestMapping(path = {"/modify/pwd"}, method = RequestMethod.GET)
    public String modifyPwdGet(Model model) {
        return "user/user-browse";
    }

    @RequestMapping(path = {"/modify/denied/role"}, method = RequestMethod.GET)
    public String modifyDeniedRoleGet(Model model) {
        return "user/user-browse";
    }

    @RequestMapping(path = {"/modify/granted/role"}, method = RequestMethod.GET)
    public String modifyGrantedRoleGet(Model model) {
        return "user/user-browse";
    }

    @RequestMapping(path = {"/modify/group"}, method = RequestMethod.GET)
    public String modifyGroupGet(Model model) {
        return "user/user-browse";
    }

    @RequestMapping(path = {"/switch"}, method = RequestMethod.GET)
    public String switchGet(Model model) {
        return "user/user-browse";
    }

}
