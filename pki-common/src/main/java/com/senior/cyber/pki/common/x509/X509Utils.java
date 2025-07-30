package com.senior.cyber.pki.common.x509;

import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

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

public class X509Utils {

    private static final Provider X509_PROVIDER = new BouncyCastleProvider();

    /**
     * @param issuerProvider    issuerProvider
     * @param issuerPrivateKey  issuerPrivateKey
     * @param issuerCertificate issuerCertificate
     * @param crlApi            URI of crl repository, crl repository have to be signed by CRL Certificate which sign by certificate issuer (*.crl)
     * @param ocspApi           URI of ocsp request/response signer, the OCSP certificate which sign by certificate issuer
     * @param x509Api           URI of the issuer certificate file (*.der)
     * @param publicKey         public key which issuer want to sign
     * @param subject           subject which issuer want to sign
     * @return a signed certificate which signed by issuerPrivateKey
     */
    public static X509Certificate issue(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate,
                                        String crlApi, String ocspApi, String x509Api,
                                        PublicKey publicKey, X500Name subject,
                                        long serial,
                                        boolean ca,
                                        Date notBefore,
                                        Date notAfter,
                                        List<Integer> keyUsages,
                                        List<KeyPurposeId> extendedKeyUsages,
                                        List<String> sans) throws CertIOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        X500Name issuerSubject = X500Name.getInstance(issuerCertificate.getSubjectX500Principal().getEncoded());
        PublicKey issuerPublicKey = issuerCertificate.getPublicKey();
        return issue(issuerProvider, issuerPrivateKey, issuerPublicKey, issuerSubject, crlApi, ocspApi, x509Api, publicKey, subject, serial, ca, notBefore, notAfter, keyUsages, extendedKeyUsages, sans);
    }

    /**
     * @param issuerProvider   issuerProvider
     * @param issuerPrivateKey issuerPrivateKey
     * @param issuerPublicKey  issuerPublicKey
     * @param issuerSubject    issuerSubject
     * @param crlApi           URI of crl repository, crl repository have to be signed by CRL Certificate which sign by certificate issuer (*.crl)
     * @param ocspApi          URI of ocsp request/response signer, the OCSP certificate which sign by certificate issuer
     * @param x509Api          URI of the issuer certificate file (*.der)
     * @param publicKey        public key which issuer want to sign
     * @param subject          subject which issuer want to sign
     * @return a signed certificate which signed by issuerPrivateKey
     */
    public static X509Certificate issue(Provider issuerProvider, PrivateKey issuerPrivateKey, PublicKey issuerPublicKey, X500Name issuerSubject,
                                        String crlApi, String ocspApi, String x509Api,
                                        PublicKey publicKey, X500Name subject,
                                        long serial,
                                        boolean ca,
                                        Date notBefore,
                                        Date notAfter,
                                        List<Integer> keyUsages,
                                        List<KeyPurposeId> extendedKeyUsages,
                                        List<String> sans) throws CertIOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerSubject, BigInteger.valueOf(serial), notBefore, notAfter, subject, publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(publicKey));
        builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerPublicKey));
        if (keyUsages != null && !keyUsages.isEmpty()) {
            int keyUsage = 0;
            for (int ku : keyUsages) {
                keyUsage = keyUsage | ku;
            }
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        }
        if (extendedKeyUsages != null && !extendedKeyUsages.isEmpty()) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(extendedKeyUsages.toArray(new KeyPurposeId[0])));
        }

        if (crlApi != null && !crlApi.isEmpty()) {
            List<DistributionPoint> distributionPoints = new ArrayList<>();
            distributionPoints.add(new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlApi))), null, null));
            builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distributionPoints.toArray(new DistributionPoint[0])));
        }
        if ((ocspApi != null && !ocspApi.isEmpty()) || (x509Api != null && !x509Api.isEmpty())) {
            List<AccessDescription> accessDescriptions = new ArrayList<>();
            if (ocspApi != null && !ocspApi.isEmpty()) {
                accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, ocspApi)));
            }
            if (x509Api != null && !x509Api.isEmpty()) {
                accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, x509Api)));
            }
            builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(accessDescriptions.toArray(new AccessDescription[0])));
        }

        List<String> ips = new ArrayList<>();
        List<String> dnses = new ArrayList<>();

        if (sans != null && !sans.isEmpty()) {
            List<String> included = new ArrayList<>();
            InetAddressValidator ipValidator = InetAddressValidator.getInstance();
            DomainValidator dnsValidator = DomainValidator.getInstance(true);
            List<GeneralName> generalNames = new ArrayList<>();
            for (String san : sans) {
                if (!included.contains(san)) {
                    if (ipValidator.isValid(san)) {
                        generalNames.add(new GeneralName(GeneralName.iPAddress, san));
                        included.add(san);
                    } else if (dnsValidator.isValid(san)) {
                        generalNames.add(new GeneralName(GeneralName.dNSName, san));
                        included.add(san);
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
        if (issuerPrivateKey instanceof RSAPrivateKey) {
            format = "RSA";
        } else if (issuerPrivateKey instanceof ECPrivateKey || "EC".equals(issuerPrivateKey.getAlgorithm())) {
            format = "ECDSA";
        } else if (issuerPrivateKey instanceof DSAPrivateKey) {
            format = "DSA";
        } else {
            format = issuerPrivateKey.getAlgorithm();
        }

        int shaSize = 256;
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
        contentSignerBuilder.setProvider(issuerProvider);
        ContentSigner contentSigner = contentSignerBuilder.build(issuerPrivateKey);

        X509CertificateHolder holder = builder.build(contentSigner);
        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        certificateConverter.setProvider(X509_PROVIDER);
        return certificateConverter.getCertificate(holder);
    }

}
