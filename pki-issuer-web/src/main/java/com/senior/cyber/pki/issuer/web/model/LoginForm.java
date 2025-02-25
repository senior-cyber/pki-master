package com.senior.cyber.pki.issuer.web.model;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.UUID;

@Setter
@Getter
public class LoginForm implements Serializable {

    private String uid;

    private String uidId = UUID.randomUUID().toString();

    private String pwd;

    private String pwdId = UUID.randomUUID().toString();

    private boolean rememberMe;

    private String rememberMeId = UUID.randomUUID().toString();

}
