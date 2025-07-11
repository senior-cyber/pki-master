package com.senior.cyber.pki.common.x509;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.joda.time.LocalDate;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;

public class RootUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static X509Certificate generate(KeyPair rootKey, PKCS10CertificationRequest csr) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, PKCSException {
        PublicKey subjectPublicKey = new JcaPEMKeyConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getPublicKey(csr.getSubjectPublicKeyInfo());

        if (!rootKey.getPublic().equals(subjectPublicKey)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CSR public key does not match root public key");
        }

        ContentVerifierProvider verifier =
                new JcaContentVerifierProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(subjectPublicKey);

        if (!csr.isSignatureValid(verifier)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CSR signature does not match root public key");
        }

        return generate(rootKey.getPrivate(), rootKey.getPublic(), csr.getSubject());
    }

    public static X509Certificate generate(PrivateKey privateKey, PublicKey publicKey, X500Name subject) {
        JcaX509ExtensionUtils utils = null;
        try {
            utils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(10).toDate();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter, subject, publicKey);
        try {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            // builder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.cRLSign | KeyUsage.keyCertSign));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(publicKey));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(publicKey));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        String format = "";
        if (privateKey instanceof RSAPrivateKey) {
            format = "RSA";
        } else if (privateKey instanceof ECPrivateKey) {
            format = "ECDSA";
        } else if (privateKey instanceof DSAPrivateKey) {
            format = "DSA";
        }

        int shaSize = 256;
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
        contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner contentSigner = null;
        try {
            contentSigner = contentSignerBuilder.build(privateKey);
        } catch (OperatorCreationException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        X509CertificateHolder holder = builder.build(contentSigner);

        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        certificateConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        try {
            return certificateConverter.getCertificate(holder);
        } catch (CertificateException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

}
