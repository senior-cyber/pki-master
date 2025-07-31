package com.senior.cyber.pki.common.x509;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

public class KeyUtils {

    public static KeyPair generate() {
        return generate(KeyFormat.EC);
    }

    public static KeyPair generate(KeyFormat format) {
        int keySize = 0;
        if (format == KeyFormat.EC) {
            keySize = 256;
        } else if (format == KeyFormat.RSA) {
            keySize = 2048;
        }
        return generate(format, keySize);
    }

    public static KeyPair generate(KeyFormat format, int keySize) {
        Provider provider = new BouncyCastleProvider();
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance(format.name(), provider);
        } catch (NoSuchAlgorithmException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

}
