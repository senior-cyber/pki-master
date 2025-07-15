package com.senior.cyber.pki.common.x509;

import org.bouncycastle.asn1.x500.X500Name;
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

public class IssuerUtils {

    public static X509Certificate generate(X509Certificate issuerCertificate, PrivateKey issuerKey, PublicKey publicKey, X500Name subject, String crlApi, String ocspApi, String x509Api, long serial) {
        Provider provider = new BouncyCastleProvider();

        JcaX509ExtensionUtils utils = null;
        try {
            utils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(5).toDate();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerCertificate, BigInteger.valueOf(serial), notBefore, notAfter, subject, publicKey);
        try {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(publicKey));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        String hex = String.format("%012X", issuerCertificate.getSerialNumber().longValueExact());

        if (crlApi != null && !crlApi.isEmpty()) {
            List<DistributionPoint> distributionPoints = new ArrayList<>();
            distributionPoints.add(new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlApi + "/crl/" + hex + ".crl"))), null, null));
            try {
                builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distributionPoints.toArray(new DistributionPoint[0])));
            } catch (CertIOException e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
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
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        X509CertificateHolder holder = builder.build(contentSigner);

        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        certificateConverter.setProvider(new BouncyCastleProvider());
        try {
            return certificateConverter.getCertificate(holder);
        } catch (CertificateException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

    public static X509Certificate generateCrlCertificate(Provider provider, X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr) {
        return generateCrlCertificate(provider, issuerCertificate, issuerKey, csr, System.currentTimeMillis());
    }

    public static X509Certificate generateCrlCertificate(Provider provider, X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, long serial) {
        BigInteger _serial = BigInteger.valueOf(serial);

        JcaX509ExtensionUtils utils = null;
        try {
            utils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();

        JcaPEMKeyConverter subjectPublicKeyConverter = new JcaPEMKeyConverter();
        subjectPublicKeyConverter.setProvider(new BouncyCastleProvider());
        PublicKey subjectPublicKey = null;
        try {
            subjectPublicKey = subjectPublicKeyConverter.getPublicKey(csr.getSubjectPublicKeyInfo());
        } catch (PEMException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        JcaContentVerifierProviderBuilder verifierBuilder = new JcaContentVerifierProviderBuilder();
        verifierBuilder.setProvider(new BouncyCastleProvider());
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
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.cRLSign));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(subjectPublicKey));
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
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        X509CertificateHolder holder = builder.build(contentSigner);

        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        certificateConverter.setProvider(new BouncyCastleProvider());
        try {
            return certificateConverter.getCertificate(holder);
        } catch (CertificateException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

    public static X509Certificate generateOcspCertificate(Provider provider, X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr) {
        return generateOcspCertificate(provider, issuerCertificate, issuerKey, csr, System.currentTimeMillis());
    }

    public static X509Certificate generateOcspCertificate(Provider provider, X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, long serial) {
        BigInteger _serial = BigInteger.valueOf(serial);

        JcaX509ExtensionUtils utils = null;
        try {
            utils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(1).toDate();

        JcaPEMKeyConverter subjectPublicKeyConverter = new JcaPEMKeyConverter();
        subjectPublicKeyConverter.setProvider(new BouncyCastleProvider());
        PublicKey subjectPublicKey = null;
        try {
            subjectPublicKey = subjectPublicKeyConverter.getPublicKey(csr.getSubjectPublicKeyInfo());
        } catch (PEMException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        JcaContentVerifierProviderBuilder verifierBuilder = new JcaContentVerifierProviderBuilder();
        verifierBuilder.setProvider(new BouncyCastleProvider());
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
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_OCSPSigning}));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));
        } catch (CertIOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        try {
            builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(subjectPublicKey));
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
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        X509CertificateHolder holder = builder.build(contentSigner);

        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        certificateConverter.setProvider(new BouncyCastleProvider());
        try {
            return certificateConverter.getCertificate(holder);
        } catch (CertificateException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

}
