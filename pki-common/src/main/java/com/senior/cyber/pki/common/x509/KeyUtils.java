package com.senior.cyber.pki.common.x509;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

public class KeyUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static KeyPair generate() throws NoSuchAlgorithmException, NoSuchProviderException {
        return generate(KeyFormat.EC);
    }

    public static KeyPair generate(KeyFormat format) throws NoSuchAlgorithmException, NoSuchProviderException {
        int keySize = 0;
        if (format == KeyFormat.DSA) {
            keySize = 512;
        } else if (format == KeyFormat.EC) {
            keySize = 256;
        } else if (format == KeyFormat.RSA) {
            keySize = 2048;
        }
        return generate(format, keySize);
    }

    public static KeyPair generate(KeyFormat format, int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(format.name(), BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

}
