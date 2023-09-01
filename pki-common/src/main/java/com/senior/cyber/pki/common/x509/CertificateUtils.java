package com.senior.cyber.pki.common.x509;

import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.LocalDate;

import java.io.IOException;
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

    public static X509Certificate generateCommon(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, String crlApi, String aiaApi) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException {
        return generateCommon(issuerCertificate, issuerKey, csr, crlApi, aiaApi, System.currentTimeMillis());
    }

    public static X509Certificate generateCommon(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, String crlApi, String aiaApi, long serial) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException {
        BigInteger _serial = BigInteger.valueOf(serial);

        boolean basicConstraintsCritical = true;
        boolean keyUsageCritical = true;

        boolean basicConstraints = false;
        boolean subjectKeyIdentifierCritical = false;
        boolean authorityKeyIdentifierCritical = false;
        boolean extendedKeyUsageCritical = false;
        boolean crlDistributionPointsCritical = false;
        boolean authorityInfoAccessCritical = false;
        boolean subjectAlternativeNameCritical = false;

        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();

        PublicKey subjectPublicKey = new JcaPEMKeyConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getPublicKey(csr.getSubjectPublicKeyInfo());

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerCertificate, _serial, notBefore, notAfter, csr.getSubject(), subjectPublicKey);
        builder.addExtension(Extension.authorityKeyIdentifier, authorityKeyIdentifierCritical, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
        builder.addExtension(Extension.subjectKeyIdentifier, subjectKeyIdentifierCritical, utils.createSubjectKeyIdentifier(subjectPublicKey));
        builder.addExtension(Extension.basicConstraints, basicConstraintsCritical, new BasicConstraints(basicConstraints));

        builder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement | KeyUsage.dataEncipherment));
        builder.addExtension(Extension.extendedKeyUsage, extendedKeyUsageCritical, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection}));

        if (crlApi != null && !crlApi.isEmpty()) {
            List<DistributionPoint> distributionPoints = new ArrayList<>();
            distributionPoints.add(new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlApi + "/crl/" + issuerCertificate.getSerialNumber().longValueExact() + ".crl"))), null, null));
            builder.addExtension(Extension.cRLDistributionPoints, crlDistributionPointsCritical, new CRLDistPoint(distributionPoints.toArray(new DistributionPoint[0])));
        }
        if (aiaApi != null && !aiaApi.isEmpty()) {
            List<AccessDescription> accessDescriptions = new ArrayList<>();
            accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, aiaApi + "/ocsp/" + issuerCertificate.getSerialNumber().longValueExact())));
            accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, aiaApi + "/x509/" + issuerCertificate.getSerialNumber().longValueExact() + ".der")));
            builder.addExtension(Extension.authorityInfoAccess, authorityInfoAccessCritical, new AuthorityInformationAccess(accessDescriptions.toArray(new AccessDescription[0])));
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
        ContentSigner contentSigner = contentSignerBuilder.build(issuerKey);
        X509CertificateHolder holder = builder.build(contentSigner);

        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

    public static X509Certificate generateTls(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, String crlApi, String aiaApi, List<String> ip, List<String> dns) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException {
        return generateTls(issuerCertificate, issuerKey, csr, crlApi, aiaApi, ip, dns, System.currentTimeMillis());
    }

    public static X509Certificate generateTls(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, String crlApi, String aiaApi, List<String> ip, List<String> dns, long serial) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException {
        BigInteger _serial = BigInteger.valueOf(serial);

        boolean basicConstraintsCritical = true;
        boolean keyUsageCritical = true;

        boolean basicConstraints = false;
        boolean subjectKeyIdentifierCritical = false;
        boolean authorityKeyIdentifierCritical = false;
        boolean extendedKeyUsageCritical = false;
        boolean crlDistributionPointsCritical = false;
        boolean authorityInfoAccessCritical = false;
        boolean subjectAlternativeNameCritical = false;

        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();

        PublicKey subjectPublicKey = new JcaPEMKeyConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getPublicKey(csr.getSubjectPublicKeyInfo());

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerCertificate, _serial, notBefore, notAfter, csr.getSubject(), subjectPublicKey);
        builder.addExtension(Extension.authorityKeyIdentifier, authorityKeyIdentifierCritical, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
        builder.addExtension(Extension.subjectKeyIdentifier, subjectKeyIdentifierCritical, utils.createSubjectKeyIdentifier(subjectPublicKey));
        builder.addExtension(Extension.basicConstraints, basicConstraintsCritical, new BasicConstraints(basicConstraints));

        builder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement | KeyUsage.dataEncipherment));
        builder.addExtension(Extension.extendedKeyUsage, extendedKeyUsageCritical, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection}));

        if (crlApi != null && !crlApi.isEmpty()) {
            List<DistributionPoint> distributionPoints = new ArrayList<>();
            distributionPoints.add(new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlApi + "/crl/" + issuerCertificate.getSerialNumber().longValueExact() + ".crl"))), null, null));
            builder.addExtension(Extension.cRLDistributionPoints, crlDistributionPointsCritical, new CRLDistPoint(distributionPoints.toArray(new DistributionPoint[0])));
        }
        if (aiaApi != null && !aiaApi.isEmpty()) {
            List<AccessDescription> accessDescriptions = new ArrayList<>();
            accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, aiaApi + "/ocsp/" + issuerCertificate.getSerialNumber().longValueExact())));
            accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, aiaApi + "/x509/" + issuerCertificate.getSerialNumber().longValueExact() + ".der")));
            builder.addExtension(Extension.authorityInfoAccess, authorityInfoAccessCritical, new AuthorityInformationAccess(accessDescriptions.toArray(new AccessDescription[0])));
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
                builder.addExtension(Extension.subjectAlternativeName, subjectAlternativeNameCritical, subjectAlternativeName);
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
        ContentSigner contentSigner = contentSignerBuilder.build(issuerKey);
        X509CertificateHolder holder = builder.build(contentSigner);

        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

}
