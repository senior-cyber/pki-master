package com.senior.cyber.pki.common.x509;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.joda.time.LocalDate;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

public class RootUtils {

    public static X509Certificate generate(Provider provider, KeyPair rootKey, PKCS10CertificationRequest csr) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        PublicKey subjectPublicKey = null;
        try {
            subjectPublicKey = new JcaPEMKeyConverter()
                    .setProvider(provider)
                    .getPublicKey(csr.getSubjectPublicKeyInfo());
        } catch (PEMException e) {
            throw new RuntimeException(e);
        }

        if (!rootKey.getPublic().equals(subjectPublicKey)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CSR public key does not match root public key");
        }

        ContentVerifierProvider verifier = null;
        try {
            verifier =
                    new JcaContentVerifierProviderBuilder()
                            .setProvider(provider)
                            .build(subjectPublicKey);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }

        try {
            if (!csr.isSignatureValid(verifier)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CSR signature does not match root public key");
            }
        } catch (PKCSException e) {
            throw new RuntimeException(e);
        }

        return generate(provider, rootKey.getPrivate(), rootKey.getPublic(), csr.getSubject());
    }

    public static X509Certificate generate(Provider provider, PrivateKey privateKey, PublicKey publicKey, X500Name subject) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        long serial = System.currentTimeMillis();
        boolean ca = true;
        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(10).toDate();
        List<Integer> keyUsages = Arrays.asList(KeyUsage.cRLSign, KeyUsage.keyCertSign);

        return PkiUtils.issue(provider, privateKey, publicKey, subject, null, null, null, null, publicKey, subject, ca, notBefore, notAfter, serial, keyUsages, null, null);
    }

    public static Map<String, X509Certificate> generateCrossRoot(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate,
                                                                 String crlApi, String ocspApi, String x509Api,
                                                                 Provider provider, PrivateKey privateKey, PublicKey publicKey, X500Name subject
    ) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        long serial = System.currentTimeMillis();
        boolean ca = true;
        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(10).toDate();
        List<Integer> keyUsages = Arrays.asList(KeyUsage.cRLSign, KeyUsage.keyCertSign);

        Map<String, X509Certificate> certificates = new HashMap<>();

        X509Certificate rootCa = PkiUtils.issue(provider, privateKey, publicKey, subject, null, null, null, null, publicKey, subject, ca, notBefore, notAfter, serial + 1, keyUsages, null, null);
        X509Certificate rootCaX = PkiUtils.issue(issuerProvider, issuerPrivateKey, issuerCertificate, crlApi, ocspApi, x509Api, null, publicKey, subject, ca, notBefore, notAfter, serial + 2, keyUsages, null, null);
        certificates.put("rootCa", rootCa);
        certificates.put("rootCaX", rootCaX);

        return certificates;
    }

}
