package com.senior.cyber.pki.issuer.web.model;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.UUID;

@Setter
@Getter
public class LoginForm implements Serializable {

    private String login;

    private String loginId = UUID.randomUUID().toString();

    private String password;

    private String passwordId = UUID.randomUUID().toString();

    private boolean rememberMe;

    private String rememberMeId = UUID.randomUUID().toString();

}
