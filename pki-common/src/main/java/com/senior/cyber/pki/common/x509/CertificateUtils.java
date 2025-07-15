package com.senior.cyber.pki.common.x509;

import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.joda.time.LocalDate;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class CertificateUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static X509Certificate generateCommon(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, String crlApi, String ocspApi, String x509Api) {
        return generateCommon(issuerCertificate, issuerKey, csr, crlApi, ocspApi, x509Api, System.currentTimeMillis());
    }

    public static X509Certificate generateCommon(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, String crlApi, String ocspApi, String x509Api, long serial) {
        BigInteger _serial = BigInteger.valueOf(serial);

        JcaX509ExtensionUtils utils = null;
        try {
            utils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();

        PublicKey subjectPublicKey = null;
        try {
            subjectPublicKey = new JcaPEMKeyConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getPublicKey(csr.getSubjectPublicKeyInfo());
        } catch (PEMException e) {
            throw new RuntimeException(e);
        }

        ContentVerifierProvider verifier = null;
        try {
            verifier =
                    new JcaContentVerifierProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(subjectPublicKey);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }

        try {
            if (!csr.isSignatureValid(verifier)) {
                throw new PKCSException("Signature verification failed");
            }
        } catch (PKCSException e) {
            throw new RuntimeException(e);
        }

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerCertificate, _serial, notBefore, notAfter, csr.getSubject(), subjectPublicKey);
        try {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth}));
            builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
            builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(subjectPublicKey));
        } catch (CertIOException e) {
            throw new RuntimeException(e);
        }

        String hex = String.format("%012X", issuerCertificate.getSerialNumber().longValueExact());

        if (crlApi != null && !crlApi.isEmpty()) {
            List<DistributionPoint> distributionPoints = new ArrayList<>();
            distributionPoints.add(new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlApi + "/crl/" + hex + ".crl"))), null, null));
            try {
                builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distributionPoints.toArray(new DistributionPoint[0])));
            } catch (CertIOException e) {
                throw new RuntimeException(e);
            }
        }
        if ((ocspApi != null && !ocspApi.isEmpty()) || (x509Api != null && !x509Api.isEmpty())) {
            List<AccessDescription> accessDescriptions = new ArrayList<>();
            if (ocspApi != null && !ocspApi.isEmpty()) {
                accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, ocspApi + "/ocsp/" + hex)));
            }
            if (x509Api != null && !x509Api.isEmpty()) {
                accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, x509Api + "/x509/" + hex + ".der")));
            }
            try {
                builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(accessDescriptions.toArray(new AccessDescription[0])));
            } catch (CertIOException e) {
                throw new RuntimeException(e);
            }
        }

        String format = "";
        if (issuerKey instanceof RSAPrivateKey) {
            format = "RSA";
        } else if (issuerKey instanceof ECPrivateKey) {
            format = "ECDSA";
        } else if (issuerKey instanceof DSAPrivateKey) {
            format = "DSA";
        }

        int shaSize = 256;
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
        contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner contentSigner = null;
        try {
            contentSigner = contentSignerBuilder.build(issuerKey);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
        X509CertificateHolder holder = builder.build(contentSigner);

        try {
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate generateTls(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, String crlApi, String ocspApi, String x509Api, List<String> ip, List<String> dns) {
        return generateTls(issuerCertificate, issuerKey, csr, crlApi, ocspApi, x509Api, ip, dns, System.currentTimeMillis());
    }

    public static X509Certificate generateTls(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, String crlApi, String ocspApi, String x509Api, List<String> ip, List<String> dns, long serial) {
        BigInteger _serial = BigInteger.valueOf(serial);

        JcaX509ExtensionUtils utils = null;
        try {
            utils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();

        PublicKey subjectPublicKey = null;
        try {
            subjectPublicKey = new JcaPEMKeyConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getPublicKey(csr.getSubjectPublicKeyInfo());
        } catch (PEMException e) {
            throw new RuntimeException(e);
        }

        ContentVerifierProvider verifier = null;
        try {
            verifier =
                    new JcaContentVerifierProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(subjectPublicKey);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }

        try {
            if (!csr.isSignatureValid(verifier)) {
                throw new PKCSException("Signature verification failed");
            }
        } catch (PKCSException e) {
            throw new RuntimeException(e);
        }

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerCertificate, _serial, notBefore, notAfter, csr.getSubject(), subjectPublicKey);
        try {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth}));
            builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
            builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(subjectPublicKey));
        } catch (CertIOException e) {
            throw new RuntimeException(e);
        }

        String hex = String.format("%012X", issuerCertificate.getSerialNumber().longValueExact());

        if (crlApi != null && !crlApi.isEmpty()) {
            List<DistributionPoint> distributionPoints = new ArrayList<>();
            distributionPoints.add(new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlApi + "/crl/" + hex + ".crl"))), null, null));
            try {
                builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distributionPoints.toArray(new DistributionPoint[0])));
            } catch (CertIOException e) {
                throw new RuntimeException(e);
            }
        }
        if ((ocspApi != null && !ocspApi.isEmpty()) || (x509Api != null && !x509Api.isEmpty())) {
            List<AccessDescription> accessDescriptions = new ArrayList<>();
            if (ocspApi != null && !ocspApi.isEmpty()) {
                accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, ocspApi + "/ocsp/" + hex)));
            }
            if (x509Api != null && !x509Api.isEmpty()) {
                accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, x509Api + "/x509/" + hex + ".der")));
            }
            try {
                builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(accessDescriptions.toArray(new AccessDescription[0])));
            } catch (CertIOException e) {
                throw new RuntimeException(e);
            }
        }

        List<String> ips = new ArrayList<>();
        List<String> dnses = new ArrayList<>();

        if (
                (ip != null && !ip.isEmpty()) || (dns != null && dns.isEmpty())
        ) {
            List<GeneralName> generalNames = new ArrayList<>();
            if (ip != null && !ip.isEmpty()) {
                InetAddressValidator validator = InetAddressValidator.getInstance();
                for (String p : ip) {
                    if (validator.isValid(p)) {
                        if (!ips.contains(p)) {
                            generalNames.add(new GeneralName(GeneralName.iPAddress, p));
                            ips.add(p);
                        }
                    }
                }
            }
            if (dns != null && !dns.isEmpty()) {
                DomainValidator validator = DomainValidator.getInstance(true);
                for (String p : dns) {
                    if (validator.isValid(p)) {
                        if (!dnses.contains(p)) {
                            generalNames.add(new GeneralName(GeneralName.dNSName, p));
                            dnses.add(p);
                        }
                    }
                }
            }
            if (!generalNames.isEmpty()) {
                GeneralNames subjectAlternativeName = new GeneralNames(generalNames.toArray(new GeneralName[0]));
                try {
                    builder.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeName);
                } catch (CertIOException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        String format = "";
        if (issuerKey instanceof RSAPrivateKey) {
            format = "RSA";
        } else if (issuerKey instanceof ECPrivateKey) {
            format = "ECDSA";
        } else if (issuerKey instanceof DSAPrivateKey) {
            format = "DSA";
        }

        int shaSize = 256;
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
        contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner contentSigner = null;
        try {
            contentSigner = contentSignerBuilder.build(issuerKey);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
        X509CertificateHolder holder = builder.build(contentSigner);

        try {
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate convert(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try (PEMParser parser = new PEMParser(new StringReader(value))) {
            Object object = parser.readObject();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
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

}
