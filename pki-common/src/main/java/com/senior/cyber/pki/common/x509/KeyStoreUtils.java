package com.senior.cyber.pki.common.x509;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

public class KeyStoreUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * for Trusted Manager Store
     *
     * @param alias
     * @param certificate
     * @return
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
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
     * @return
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
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
     * @param alias
     * @param privateKey
     * @param certificate
     * @return
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
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
     * @param alias
     * @param privateKey
     * @param certificateChain
     * @return
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
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
