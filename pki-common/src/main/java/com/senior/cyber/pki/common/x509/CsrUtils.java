package com.senior.cyber.pki.common.x509;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public class CsrUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static PKCS10CertificationRequest generate(KeyPair key, X500Name subject) throws OperatorCreationException {
        int shaSize = 256;
        return generate(key, subject, shaSize);
    }

    public static PKCS10CertificationRequest generate(KeyPair key, X500Name subject, int shaSize) throws OperatorCreationException {
        String format = "";
        if (key.getPublic() instanceof RSAPublicKey) {
            format = "RSA";
        } else if (key.getPublic() instanceof ECPublicKey) {
            format = "ECDSA";
        } else if (key.getPublic() instanceof DSAPublicKey) {
            format = "DSA";
        }
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, key.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
        csBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner contentSigner = csBuilder.build(key.getPrivate());
        return builder.build(contentSigner);
    }

}
