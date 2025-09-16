package com.senior.cyber.pki.common.x509;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.LocalDate;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class IssuerUtils {

    private static final Provider X509_PROVIDER = new BouncyCastleProvider();

    public static X509Certificate generate(Provider provider, X509Certificate issuerCertificate, PrivateKey issuerKey, PublicKey publicKey, X500Name subject,
                                           String crlApi,
                                           String ocspApi,
                                           String x509Api,
                                           long serial) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        boolean ca = true;
        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(5).toDate();
        List<Integer> keyUsages = Arrays.asList(KeyUsage.cRLSign, KeyUsage.keyCertSign);

        String hex = String.format("%012X", issuerCertificate.getSerialNumber().longValueExact());
        String _crlApi = crlApi + "/" + hex + ".crl";
        String _ocspApi = ocspApi + "/" + hex;
        String _x509Api = x509Api + "/" + hex + ".der";

        return PkiUtils.issue(provider, issuerKey, issuerCertificate, _crlApi, _ocspApi, _x509Api, null, publicKey, subject, ca, notBefore, notAfter, serial, keyUsages, null, null);
    }

    public static X509Certificate generateCrlCertificate(Provider provider, X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr) throws PEMException, NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        return generateCrlCertificate(provider, issuerCertificate, issuerKey, csr, System.currentTimeMillis());
    }

    public static X509Certificate generateCrlCertificate(Provider provider, X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, long serial) throws PEMException, NoSuchAlgorithmException, OperatorCreationException, CertIOException, CertificateException {
        boolean ca = false;
        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();
        List<Integer> keyUsages = List.of(KeyUsage.cRLSign);

        JcaPEMKeyConverter subjectPublicKeyConverter = new JcaPEMKeyConverter();
        subjectPublicKeyConverter.setProvider(X509_PROVIDER);
        PublicKey publicKey = subjectPublicKeyConverter.getPublicKey(csr.getSubjectPublicKeyInfo());

        X500Name subject = csr.getSubject();

        return PkiUtils.issue(provider, issuerKey, issuerCertificate, null, null, null, null, publicKey, subject, ca, notBefore, notAfter, serial, keyUsages, null, null);
    }

    public static X509Certificate generateOcspCertificate(Provider provider, X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr) throws PEMException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        return generateOcspCertificate(provider, issuerCertificate, issuerKey, csr, System.currentTimeMillis());
    }

    public static X509Certificate generateOcspCertificate(Provider provider, X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, long serial) throws PEMException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        boolean ca = false;
        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();
        List<Integer> keyUsages = List.of(KeyUsage.digitalSignature);
        List<KeyPurposeId> extendedKeyUsages = List.of(KeyPurposeId.id_kp_OCSPSigning);

        JcaPEMKeyConverter subjectPublicKeyConverter = new JcaPEMKeyConverter();
        subjectPublicKeyConverter.setProvider(X509_PROVIDER);
        PublicKey publicKey = subjectPublicKeyConverter.getPublicKey(csr.getSubjectPublicKeyInfo());

        X500Name subject = csr.getSubject();

        return PkiUtils.issue(provider, issuerKey, issuerCertificate, null, null, null, null, publicKey, subject, ca, notBefore, notAfter, serial, keyUsages, extendedKeyUsages, null);
    }

}
