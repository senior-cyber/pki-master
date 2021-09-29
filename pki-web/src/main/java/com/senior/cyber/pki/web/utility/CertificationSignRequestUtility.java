package com.senior.cyber.pki.web.utility;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public class CertificationSignRequestUtility {

    public static PKCS10CertificationRequest generate(PrivateKey privateKey, PublicKey publicKey, X500Name subject) throws OperatorCreationException {
        return generate(privateKey, publicKey, subject, 256);
    }

    public static PKCS10CertificationRequest generate(PrivateKey privateKey, PublicKey publicKey, X500Name subject, int keySize) throws OperatorCreationException {
        String format = "";
        if (publicKey instanceof RSAPublicKey) {
            format = "RSA";
        } else if (publicKey instanceof ECPublicKey) {
            format = "ECDSA";
        } else if (publicKey instanceof DSAPublicKey) {
            format = "DSA";
        }
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA" + keySize + "WITH" + format);
        csBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner contentSigner = csBuilder.build(privateKey);
        return builder.build(contentSigner);
    }

}
