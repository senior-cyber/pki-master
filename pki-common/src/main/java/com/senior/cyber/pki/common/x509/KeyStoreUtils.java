package com.senior.cyber.pki.common.x509;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

public class KeyStoreUtils {

    /**
     * for Trusted Manager Store
     *
     */
    public static KeyStore generateKeyStore(String alias, X509Certificate certificate) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry(alias, certificate);
            return keyStore;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            // should never happen
            return null;
        }
    }

    /**
     * for Trusted Manager Store
     *
     */
    public static KeyStore generateKeyStore(Map<String, X509Certificate> certificates) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            for (Map.Entry<String, X509Certificate> certificate : certificates.entrySet()) {
                keyStore.setCertificateEntry(certificate.getKey(), certificate.getValue());
            }
            return keyStore;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            // should never happen
            return null;
        }
    }

    /**
     * for Key Manager Store 2Ways TLS
     *
     */
    public static KeyStore generateKeyStore(String alias, PrivateKey privateKey, X509Certificate certificate) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setKeyEntry(alias, privateKey, "".toCharArray(), new Certificate[]{certificate});
            return keyStore;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            // should never happen
            return null;
        }
    }

    /**
     * for Key Manager Store to host the secure port
     *
     */
    public static KeyStore generateKeyStore(String alias, PrivateKey privateKey, X509Certificate[] certificateChain) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setKeyEntry(alias, privateKey, "".toCharArray(), certificateChain);
            return keyStore;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            // should never happen
            return null;
        }
    }

}
