package com.senior.cyber.pki.issuer.web.model;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.UUID;

@Setter
@Getter
public class UserCreateInfoForm implements Serializable {

    private String login;

    private String loginId = UUID.randomUUID().toString();

    private String password;

    private String passwordId = UUID.randomUUID().toString();

    private String emailAddress;

    private String emailAddressId = UUID.randomUUID().toString();

}
