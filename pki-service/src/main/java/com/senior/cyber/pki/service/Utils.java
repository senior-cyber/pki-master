package com.senior.cyber.pki.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class Utils {

    public static final BouncyCastleProvider BC = new BouncyCastleProvider();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

}