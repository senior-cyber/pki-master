package com.senior.cyber.pki.common.x509;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

public class ChainUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static boolean validate(List<X509Certificate> certificateChain) {
        try {
            for (int i = certificateChain.size() - 1; i > 0; i--) {
                X509Certificate certificate = certificateChain.get(i);
                X509Certificate issuerCertificate = certificateChain.get(i - 1);
                certificate.verify(issuerCertificate.getPublicKey());
                if (!certificate.getIssuerX500Principal().equals(issuerCertificate.getSubjectX500Principal())) {
                    return false;
                }
            }
            return true;
        } catch (CertificateException | SignatureException | NoSuchProviderException | InvalidKeyException |
                 NoSuchAlgorithmException e) {
            return false;
        }
    }

}
