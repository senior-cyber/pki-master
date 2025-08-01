package com.senior.cyber.pki.common.x509;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;

public class SSLContextUtils {

    public static SSLServerSocketFactory createSSLServerSocketFactory(X509TrustManager trustManager, X509KeyManager keyManager) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(new KeyManager[]{keyManager}, new TrustManager[]{trustManager}, new SecureRandom());
            return context.getServerSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            return null;
        }
    }

    public static SSLServerSocketFactory createSSLServerSocketFactory(X509KeyManager keyManager) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(new KeyManager[]{keyManager}, null, new SecureRandom());
            return context.getServerSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            return null;
        }
    }

    public static SSLSocketFactory createSSLSocketFactory(X509TrustManager trustManager, X509KeyManager keyManager) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(new KeyManager[]{keyManager}, new TrustManager[]{trustManager}, new SecureRandom());
            return context.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            return null;
        }
    }

    public static SSLSocketFactory createSSLSocketFactory(X509TrustManager trustManager) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{trustManager}, new SecureRandom());
            return context.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            return null;
        }
    }

    public static SSLContext createSSLContext(X509TrustManager trustManager) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{trustManager}, new SecureRandom());
            return context;
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            return null;
        }
    }

    public static SSLContext createSSLContext(X509TrustManager trustManager, X509KeyManager keyManager) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(new KeyManager[]{keyManager}, new TrustManager[]{trustManager}, new SecureRandom());
            return context;
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            return null;
        }
    }

    public static X509KeyManager createKeyManager(KeyStore keyStore, String keyPassword) {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyManager[] keystoreManagers = null;
            kmf.init(keyStore, keyPassword == null ? new char[]{} : keyPassword.toCharArray());
            keystoreManagers = kmf.getKeyManagers();
            return (X509KeyManager) keystoreManagers[0];
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            return null;
        }
    }

    public static X509TrustManager createTrustManager(KeyStore keyStore) {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
            tmf.init(keyStore);
            TrustManager[] trustManagers = tmf.getTrustManagers();
            if (trustManagers.length != 1) {
                throw new IllegalArgumentException("More than 1 TrustManager created.");
            }
            if (!(trustManagers[0] instanceof X509TrustManager)) {
                throw new IllegalArgumentException("TrustManager not of type X509: " + trustManagers[0].getClass());
            }
            return (X509TrustManager) trustManagers[0];
        } catch (NoSuchAlgorithmException | KeyStoreException ex) {
            return null;
        }
    }

    public static KeyStore loadKeyStore(String type, File store, String password) {
        try (InputStream stream = new FileInputStream(store)) {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(stream, password == null ? new char[]{} : password.toCharArray());
            return keyStore;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            return null;
        }
    }

}
