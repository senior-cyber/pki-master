package com.senior.cyber.pki.common.x509;

import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.joda.time.LocalDate;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class CertificateUtils {

    public static X509Certificate generateCommon(X509Certificate issuerCertificate, PrivateKey issuerKey, PublicKey publicKey, X500Name subject, String crlApi, String ocspApi, String x509Api) {
        return generateCommon(issuerCertificate, issuerKey, publicKey, subject, crlApi, ocspApi, x509Api, System.currentTimeMillis());
    }

    public static X509Certificate generateCommon(X509Certificate issuerCertificate, PrivateKey issuerKey, PublicKey publicKey, X500Name subject, String crlApi, String ocspApi, String x509Api, long serial) {
        Provider provider = new BouncyCastleProvider();

        BigInteger _serial = BigInteger.valueOf(serial);

        JcaX509ExtensionUtils utils = null;
        try {
            utils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerCertificate, _serial, notBefore, notAfter, subject, publicKey);
        try {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth}));
            builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
            builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(publicKey));
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
        } else {
            format = issuerKey.getAlgorithm();
        }

        int shaSize = 256;
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
        contentSignerBuilder.setProvider(provider);
        ContentSigner contentSigner = null;
        try {
            contentSigner = contentSignerBuilder.build(issuerKey);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
        X509CertificateHolder holder = builder.build(contentSigner);

        try {
            return new JcaX509CertificateConverter()
                    .setProvider(provider)
                    .getCertificate(holder);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate generateTls(X509Certificate issuerCertificate, PrivateKey issuerKey, PublicKey publicKey, X500Name subject, String crlApi, String ocspApi, String x509Api, List<String> ip, List<String> dns) {
        return generateTls(issuerCertificate, issuerKey, publicKey, subject, crlApi, ocspApi, x509Api, ip, dns, System.currentTimeMillis());
    }

    public static X509Certificate generateTls(X509Certificate issuerCertificate, PrivateKey issuerKey, PublicKey publicKey, X500Name subject, String crlApi, String ocspApi, String x509Api, List<String> ip, List<String> dns, long serial) {
        Provider provider = new BouncyCastleProvider();
        BigInteger _serial = BigInteger.valueOf(serial);

        JcaX509ExtensionUtils utils = null;
        try {
            utils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerCertificate, _serial, notBefore, notAfter, subject, publicKey);
        try {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth}));
            builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
            builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(publicKey));
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
        } else {
            format = issuerKey.getAlgorithm();
        }

        int shaSize = 256;
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
        contentSignerBuilder.setProvider(provider);
        ContentSigner contentSigner = null;
        try {
            contentSigner = contentSignerBuilder.build(issuerKey);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
        X509CertificateHolder holder = builder.build(contentSigner);

        try {
            return new JcaX509CertificateConverter()
                    .setProvider(provider)
                    .getCertificate(holder);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate convert(String value) {
        Provider provider = new BouncyCastleProvider();

        if (value == null || value.isEmpty()) {
            return null;
        }
        try (PEMParser parser = new PEMParser(new StringReader(value))) {
            Object object = parser.readObject();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            converter.setProvider(provider);
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
