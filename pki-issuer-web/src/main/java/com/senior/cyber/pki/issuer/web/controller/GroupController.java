package com.senior.cyber.pki.issuer.web.controller;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping(path = "/group")
@RequiredArgsConstructor
public class GroupController {

    private static final Logger LOGGER = LoggerFactory.getLogger(GroupController.class);

    @RequestMapping(path = {"/browse"}, method = RequestMethod.GET)
    public String browseGet(Model model) {
        return "user/user-browse";
    }

    @RequestMapping(path = {"/modify/info"}, method = RequestMethod.GET)
    public String modifyInfoGet(Model model) {
        return "user/user-browse";
    }

    @RequestMapping(path = {"/modify/member"}, method = RequestMethod.GET)
    public String modifyMemberGet(Model model) {
        return "user/user-browse";
    }

    @RequestMapping(path = {"/modify/role"}, method = RequestMethod.GET)
    public String modifyRoleGet(Model model) {
        return "user/user-browse";
    }

}
