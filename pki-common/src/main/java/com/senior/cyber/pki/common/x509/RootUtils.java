package com.senior.cyber.pki.common.x509;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
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
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.joda.time.LocalDate;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
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
        return generate(rootKey, csr, System.currentTimeMillis());
    }

    public static X509Certificate generate(KeyPair rootKey, PKCS10CertificationRequest csr, long serial) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, PKCSException {
        BigInteger _serial = BigInteger.valueOf(serial);
        boolean basicConstraintsCritical = true;
        boolean keyUsageCritical = true;
        boolean basicConstraints = true;

        boolean subjectKeyIdentifierCritical = false;
        boolean authorityKeyIdentifierCritical = false;
        boolean extendedKeyUsageCritical = false;
        boolean crlDistributionPointsCritical = false;
        boolean authorityInfoAccessCritical = false;
        boolean subjectAlternativeNameCritical = false;

        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(10).toDate();

        PublicKey subjectPublicKey = new JcaPEMKeyConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getPublicKey(csr.getSubjectPublicKeyInfo());

        ContentVerifierProvider verifier =
                new JcaContentVerifierProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(subjectPublicKey);

        if (!csr.isSignatureValid(verifier)) {
            throw new PKCSException("Signature verification failed");
        }

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(csr.getSubject(), _serial, notBefore, notAfter, csr.getSubject(), subjectPublicKey);
        builder.addExtension(Extension.authorityKeyIdentifier, authorityKeyIdentifierCritical, utils.createAuthorityKeyIdentifier(subjectPublicKey));
        builder.addExtension(Extension.subjectKeyIdentifier, subjectKeyIdentifierCritical, utils.createSubjectKeyIdentifier(subjectPublicKey));
        builder.addExtension(Extension.basicConstraints, basicConstraintsCritical, new BasicConstraints(basicConstraints));
        builder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.cRLSign | KeyUsage.keyCertSign));

        String format = "";
        if (rootKey.getPrivate() instanceof RSAPrivateKey) {
            format = "RSA";
        } else if (rootKey.getPrivate() instanceof ECPrivateKey) {
            format = "ECDSA";
        } else if (rootKey.getPrivate() instanceof DSAPrivateKey) {
            format = "DSA";
        }

        int shaSize = 256;
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
        contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner contentSigner = contentSignerBuilder.build(rootKey.getPrivate());
        X509CertificateHolder holder = builder.build(contentSigner);

        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

}
