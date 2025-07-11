package com.senior.cyber.pki.common.x509;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
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

public class IssuerUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static X509Certificate generate(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, String crlApi, String aiaApi, long serial) {
        boolean basicConstraintsCritical = true;
        boolean keyUsageCritical = true;
        boolean basicConstraints = true;

        boolean subjectKeyIdentifierCritical = false;
        boolean authorityKeyIdentifierCritical = false;
        boolean extendedKeyUsageCritical = false;
        boolean crlDistributionPointsCritical = false;
        boolean authorityInfoAccessCritical = false;
        boolean subjectAlternativeNameCritical = false;

        JcaX509ExtensionUtils utils = null;
        try {
            utils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(5).toDate();

        JcaPEMKeyConverter subjectPublicKeyConverter = new JcaPEMKeyConverter();
        subjectPublicKeyConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        PublicKey subjectPublicKey = null;
        try {
            subjectPublicKey = subjectPublicKeyConverter.getPublicKey(csr.getSubjectPublicKeyInfo());
        } catch (PEMException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        JcaContentVerifierProviderBuilder verifierBuilder = new JcaContentVerifierProviderBuilder();
        verifierBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentVerifierProvider verifier = null;
        try {
            verifier = verifierBuilder.build(subjectPublicKey);
        } catch (OperatorCreationException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        try {
            if (!csr.isSignatureValid(verifier)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CSR signature does not match root public key");
            }
        } catch (PKCSException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerCertificate, BigInteger.valueOf(serial), notBefore, notAfter, csr.getSubject(), subjectPublicKey);
        try {
            builder.addExtension(Extension.authorityKeyIdentifier, authorityKeyIdentifierCritical, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.subjectKeyIdentifier, subjectKeyIdentifierCritical, utils.createSubjectKeyIdentifier(subjectPublicKey));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.basicConstraints, basicConstraintsCritical, new BasicConstraints(basicConstraints));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.cRLSign | KeyUsage.keyCertSign));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.extendedKeyUsage, extendedKeyUsageCritical, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        if (crlApi != null && !crlApi.isEmpty()) {
            List<DistributionPoint> distributionPoints = new ArrayList<>();
            distributionPoints.add(new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlApi + "/crl/" + serial + ".crl"))), null, null));
            try {
                builder.addExtension(Extension.cRLDistributionPoints, crlDistributionPointsCritical, new CRLDistPoint(distributionPoints.toArray(new DistributionPoint[0])));
            } catch (CertIOException e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
            }
        }
        if (aiaApi != null && !aiaApi.isEmpty()) {
            List<AccessDescription> accessDescriptions = new ArrayList<>();
            accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, aiaApi + "/ocsp/" + serial)));
            accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, aiaApi + "/x509/" + serial + ".der")));
            try {
                builder.addExtension(Extension.authorityInfoAccess, authorityInfoAccessCritical, new AuthorityInformationAccess(accessDescriptions.toArray(new AccessDescription[0])));
            } catch (CertIOException e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
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

    public static X509Certificate generateCrlCertificate(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr) {
        return generateCrlCertificate(issuerCertificate, issuerKey, csr, System.currentTimeMillis());
    }

    public static X509Certificate generateCrlCertificate(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, long serial) {
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

        JcaX509ExtensionUtils utils = null;
        try {
            utils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();

        JcaPEMKeyConverter subjectPublicKeyConverter = new JcaPEMKeyConverter();
        subjectPublicKeyConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        PublicKey subjectPublicKey = null;
        try {
            subjectPublicKey = subjectPublicKeyConverter.getPublicKey(csr.getSubjectPublicKeyInfo());
        } catch (PEMException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        JcaContentVerifierProviderBuilder verifierBuilder = new JcaContentVerifierProviderBuilder();
        verifierBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentVerifierProvider verifier = null;
        try {
            verifier = verifierBuilder.build(subjectPublicKey);
        } catch (OperatorCreationException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        try {
            if (!csr.isSignatureValid(verifier)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CSR signature does not match root public key");
            }
        } catch (PKCSException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerCertificate, _serial, notBefore, notAfter, csr.getSubject(), subjectPublicKey);
        try {
            builder.addExtension(Extension.authorityKeyIdentifier, authorityKeyIdentifierCritical, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.subjectKeyIdentifier, subjectKeyIdentifierCritical, utils.createSubjectKeyIdentifier(subjectPublicKey));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.basicConstraints, basicConstraintsCritical, new BasicConstraints(basicConstraints));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement | KeyUsage.dataEncipherment));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.extendedKeyUsage, extendedKeyUsageCritical, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection}));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
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

    public static X509Certificate generateOcspCertificate(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr) {
        return generateOcspCertificate(issuerCertificate, issuerKey, csr, System.currentTimeMillis());
    }

    public static X509Certificate generateOcspCertificate(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, long serial) {
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

        JcaX509ExtensionUtils utils = null;
        try {
            utils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();

        JcaPEMKeyConverter subjectPublicKeyConverter = new JcaPEMKeyConverter();
        subjectPublicKeyConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        PublicKey subjectPublicKey = null;
        try {
            subjectPublicKey = subjectPublicKeyConverter.getPublicKey(csr.getSubjectPublicKeyInfo());
        } catch (PEMException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        JcaContentVerifierProviderBuilder verifierBuilder = new JcaContentVerifierProviderBuilder();
        verifierBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentVerifierProvider verifier = null;
        try {
            verifier = verifierBuilder.build(subjectPublicKey);
        } catch (OperatorCreationException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        try {
            if (!csr.isSignatureValid(verifier)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CSR signature does not match root public key");
            }
        } catch (PKCSException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerCertificate, _serial, notBefore, notAfter, csr.getSubject(), subjectPublicKey);
        try {
            builder.addExtension(Extension.authorityKeyIdentifier, authorityKeyIdentifierCritical, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.subjectKeyIdentifier, subjectKeyIdentifierCritical, utils.createSubjectKeyIdentifier(subjectPublicKey));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.basicConstraints, basicConstraintsCritical, new BasicConstraints(basicConstraints));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement | KeyUsage.dataEncipherment));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.extendedKeyUsage, extendedKeyUsageCritical, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection}));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
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
