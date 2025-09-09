package com.senior.cyber.pki.common.x509;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.joda.time.LocalDate;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

public class CertificateUtils {

    private static BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    public static X509Certificate generateCommon(Provider provider, X509Certificate issuerCertificate, PrivateKey issuerKey, PublicKey publicKey, X500Name subject, String crlApi, String ocspApi, String x509Api) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        return generateCommon(provider, issuerCertificate, issuerKey, publicKey, subject, crlApi, ocspApi, x509Api, System.currentTimeMillis());
    }

    public static X509Certificate generateCommon(Provider provider, X509Certificate issuerCertificate, PrivateKey issuerKey, PublicKey publicKey, X500Name subject, String crlApi, String ocspApi, String x509Api, long serial) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        boolean ca = false;
        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();
        List<Integer> keyUsages = List.of(KeyUsage.digitalSignature, KeyUsage.keyEncipherment);
        List<KeyPurposeId> extendedKeyUsages = List.of(KeyPurposeId.id_kp_serverAuth);

        String hex = String.format("%012X", issuerCertificate.getSerialNumber().longValueExact());

        String _crlApi = crlApi + "/crl/" + hex + ".crl";
        String _ocspApi = ocspApi + "/ocsp/" + hex;
        String _x509Api = x509Api + "/x509/" + hex;

        return PkiUtils.issue(provider, issuerKey, issuerCertificate, _crlApi, _ocspApi, _x509Api, null, publicKey, subject, ca, notBefore, notAfter, serial, keyUsages, extendedKeyUsages, null);
    }

    public static X509Certificate generateTlsClient(Provider provider, X509Certificate issuerCertificate, PrivateKey issuerKey, PublicKey publicKey, X500Name subject, String crlApi, String ocspApi, String x509Api, List<String> sans, long serial) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        boolean ca = false;
        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();
        List<Integer> keyUsages = List.of(KeyUsage.digitalSignature, KeyUsage.keyEncipherment);
        List<KeyPurposeId> extendedKeyUsages = List.of(KeyPurposeId.id_kp_clientAuth);

        String hex = String.format("%012X", issuerCertificate.getSerialNumber().longValueExact());

        String _crlApi = crlApi + "/crl/" + hex + ".crl";
        String _ocspApi = ocspApi + "/ocsp/" + hex;
        String _x509Api = x509Api + "/x509/" + hex;

        return PkiUtils.issue(provider, issuerKey, issuerCertificate, _crlApi, _ocspApi, _x509Api, null, publicKey, subject, ca, notBefore, notAfter, serial, keyUsages, extendedKeyUsages, sans);
    }

    public static X509Certificate generateTlsServer(Provider provider, X509Certificate issuerCertificate, PrivateKey issuerKey, PublicKey publicKey, X500Name subject, String crlApi, String ocspApi, String x509Api, List<String> sans, long serial) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        boolean ca = false;
        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();
        List<Integer> keyUsages = List.of(KeyUsage.digitalSignature, KeyUsage.keyEncipherment);
        List<KeyPurposeId> extendedKeyUsages = List.of(KeyPurposeId.id_kp_serverAuth);

        String hex = String.format("%012X", issuerCertificate.getSerialNumber().longValueExact());

        String _crlApi = crlApi + "/crl/" + hex + ".crl";
        String _ocspApi = ocspApi + "/ocsp/" + hex;
        String _x509Api = x509Api + "/x509/" + hex;

        return PkiUtils.issue(provider, issuerKey, issuerCertificate, _crlApi, _ocspApi, _x509Api, null, publicKey, subject, ca, notBefore, notAfter, serial, keyUsages, extendedKeyUsages, sans);
    }

    public static X509Certificate convert(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try (PEMParser parser = new PEMParser(new StringReader(value))) {
            Object object = parser.readObject();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            converter.setProvider(PROVIDER);
            if (object instanceof JcaX509CertificateHolder holder) {
                return converter.getCertificate(holder);
            } else if (object instanceof X509CertificateHolder holder) {
                return converter.getCertificate(holder);
            } else {
                throw new UnsupportedOperationException(object.getClass().getName());
            }
        } catch (CertificateException | IOException e) {
            return null;
        }
    }

    public static String convert(X509Certificate value) {
        if (value == null) {
            return null;
        }
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
            writer.writeObject(value);
        } catch (IOException e) {
            return null;
        }
        return pem.toString();
    }

    public static String convert(List<X509Certificate> values) {
        StringWriter buf = new StringWriter();
        for (Certificate value : values) {
            if (value == null) {
                return null;
            }
            StringWriter pem = new StringWriter();
            try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
                writer.writeObject(value);
            } catch (IOException e) {
                return null;
            }
            buf.write(pem.toString());
        }
        return buf.toString();
    }

}
