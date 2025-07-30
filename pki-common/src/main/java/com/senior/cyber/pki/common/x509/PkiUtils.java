package com.senior.cyber.pki.common.x509;

import com.senior.cyber.pki.common.ssh.OpenSshCertificateBuilder;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
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
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class PkiUtils {

    private static final Provider X509_PROVIDER = new BouncyCastleProvider();

    /**
     * @param issuerProvider    issuerProvider
     * @param issuerPrivateKey  issuerPrivateKey
     * @param issuerCertificate issuerCertificate
     * @param crl               URI of crl repository, crl repository have to be signed by CRL Certificate which sign by certificate issuer (*.crl)
     * @param ocsp              URI of ocsp request/response signer, the OCSP certificate which sign by certificate issuer
     * @param caIssuer          URI of the issuer certificate file (*.der)
     * @param publicKey         public key which issuer want to sign
     * @param subject           subject which issuer want to sign
     * @return a signed certificate which signed by issuerPrivateKey
     */
    public static X509Certificate issue(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate,
                                        String crl, String ocsp, String caIssuer, String crlIssuer,
                                        PublicKey publicKey, X500Name subject,
                                        boolean ca, Date notBefore, Date notAfter, long serial,
                                        List<Integer> keyUsages,
                                        List<KeyPurposeId> extendedKeyUsages,
                                        List<String> sans) throws CertIOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        X500Name issuerSubject = X500Name.getInstance(issuerCertificate.getSubjectX500Principal().getEncoded());
        PublicKey issuerPublicKey = issuerCertificate.getPublicKey();
        return issue(issuerProvider, issuerPrivateKey, issuerPublicKey, issuerSubject, crl, ocsp, caIssuer, crlIssuer, publicKey, subject, ca, notBefore, notAfter, serial, keyUsages, extendedKeyUsages, sans);
    }

    /**
     * @param issuerProvider   issuerProvider
     * @param issuerPrivateKey issuerPrivateKey
     * @param issuerPublicKey  issuerPublicKey
     * @param issuerSubject    issuerSubject
     * @param crl              URI of crl repository, crl repository have to be signed by CRL Certificate which sign by certificate issuer (*.crl)
     * @param ocsp             URI of ocsp request/response signer, the OCSP certificate which sign by certificate issuer
     * @param caIssuer         URI of the issuer certificate file (*.der)
     * @param publicKey        public key which issuer want to sign
     * @param subject          subject which issuer want to sign
     * @return a signed certificate which signed by issuerPrivateKey
     */
    public static X509Certificate issue(Provider issuerProvider, PrivateKey issuerPrivateKey, PublicKey issuerPublicKey, X500Name issuerSubject,
                                        String crl, String ocsp, String caIssuer, String crlIssuer,
                                        PublicKey publicKey, X500Name subject,
                                        boolean ca, Date notBefore, Date notAfter, long serial,
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

        if (crl != null && !crl.isEmpty()) {
            List<DistributionPoint> distributionPoints = new ArrayList<>();
            if (crlIssuer == null || crlIssuer.isBlank()) {
                distributionPoints.add(new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crl))), null, null));
            } else {
                GeneralNames _crlIssuer = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlIssuer));
                int reasonFlags = ReasonFlags.keyCompromise | ReasonFlags.cACompromise | ReasonFlags.affiliationChanged | ReasonFlags.superseded | ReasonFlags.cessationOfOperation | ReasonFlags.certificateHold | ReasonFlags.privilegeWithdrawn | ReasonFlags.aACompromise;
                distributionPoints.add(new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crl))), new ReasonFlags(reasonFlags), _crlIssuer));
            }
            builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distributionPoints.toArray(new DistributionPoint[0])));
        }
        if ((ocsp != null && !ocsp.isEmpty()) || (caIssuer != null && !caIssuer.isEmpty())) {
            List<AccessDescription> accessDescriptions = new ArrayList<>();
            if (ocsp != null && !ocsp.isEmpty()) {
                accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, ocsp)));
            }
            if (caIssuer != null && !caIssuer.isEmpty()) {
                accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, caIssuer)));
            }
            builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(accessDescriptions.toArray(new AccessDescription[0])));
        }

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

    public static X509Certificate issueRootCertificate(Provider issuerProvider, PrivateKey privateKey, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        List<Integer> keyUsages = Arrays.asList(KeyUsage.cRLSign, KeyUsage.keyCertSign);
        return issue(issuerProvider, privateKey, publicKey, subject, null, null, null, null, publicKey, subject, true, notBefore, notAfter, serial, keyUsages, null, null);
    }

    public static X509Certificate issueIntermediateCertificate(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate, String crl, String ocsp, String caIssuer, String crlIssuer, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        List<Integer> keyUsages = Arrays.asList(KeyUsage.cRLSign, KeyUsage.keyCertSign);
        return issue(issuerProvider, issuerPrivateKey, issuerCertificate, crl, ocsp, caIssuer, crlIssuer, publicKey, subject, true, notBefore, notAfter, serial, keyUsages, null, null);
    }

    public static CrossSignRoot issueCrossSignRootCertificate(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate, String crl, String ocsp, String caIssuer, String crlIssuer, Provider provider, PrivateKey privateKey, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        X509Certificate root = issueRootCertificate(provider, privateKey, publicKey, subject, notBefore, notAfter, serial);
        X509Certificate crossRoot = issueIntermediateCertificate(issuerProvider, issuerPrivateKey, issuerCertificate, crl, ocsp, caIssuer, crlIssuer, publicKey, subject, notBefore, notAfter, serial + 1);
        return new CrossSignRoot(root, crossRoot);
    }

    public static X509Certificate issueLeafCertificate(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate, String crl, String ocsp, String caIssuer, String crlIssuer, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial, List<Integer> keyUsages, List<KeyPurposeId> extendedKeyUsages, List<String> sans) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        return issue(issuerProvider, issuerPrivateKey, issuerCertificate, crl, ocsp, caIssuer, crlIssuer, publicKey, subject, false, notBefore, notAfter, serial, keyUsages, extendedKeyUsages, sans);
    }

    public static X509Certificate issueCrlCertificate(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate, String crl, String ocsp, String caIssuer, String crlIssuer, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        List<Integer> keyUsages = List.of(KeyUsage.cRLSign);
        return issueLeafCertificate(issuerProvider, issuerPrivateKey, issuerCertificate, crl, ocsp, caIssuer, crlIssuer, publicKey, subject, notBefore, notAfter, serial, keyUsages, null, null);
    }

    public static X509Certificate issueOcspCertificate(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate, String crl, String ocsp, String caIssuer, String crlIssuer, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        List<Integer> keyUsages = List.of(KeyUsage.digitalSignature);
        List<KeyPurposeId> extendedKeyUsages = List.of(KeyPurposeId.id_kp_OCSPSigning);
        return issueLeafCertificate(issuerProvider, issuerPrivateKey, issuerCertificate, crl, ocsp, caIssuer, crlIssuer, publicKey, subject, notBefore, notAfter, serial, keyUsages, extendedKeyUsages, null);
    }

    public static X509Certificate issueClientCertificate(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate, String crl, String ocsp, String caIssuer, String crlIssuer, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        List<Integer> keyUsages = List.of(KeyUsage.digitalSignature, KeyUsage.keyEncipherment);
        List<KeyPurposeId> extendedKeyUsages = List.of(KeyPurposeId.id_kp_clientAuth);
        return issueLeafCertificate(issuerProvider, issuerPrivateKey, issuerCertificate, crl, ocsp, caIssuer, crlIssuer, publicKey, subject, notBefore, notAfter, serial, keyUsages, extendedKeyUsages, null);
    }

    public static X509Certificate issueServerCertificate(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate, String crl, String ocsp, String caIssuer, String crlIssuer, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial, List<String> sans) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        List<Integer> keyUsages = List.of(KeyUsage.digitalSignature, KeyUsage.keyEncipherment);
        List<KeyPurposeId> extendedKeyUsages = List.of(KeyPurposeId.id_kp_serverAuth);
        return issueLeafCertificate(issuerProvider, issuerPrivateKey, issuerCertificate, crl, ocsp, caIssuer, crlIssuer, publicKey, subject, notBefore, notAfter, serial, keyUsages, extendedKeyUsages, sans);
    }

    public static OpenSshCertificate issueSshCertificate(Provider issuerProvider, RSAPrivateKey issuerPrivateKey, RSAPublicKey issuerPublicKey, RSAPublicKey publicKey, String username, Date notBefore, Date notAfter) throws Exception {
        OpenSshCertificateBuilder openSshCertificateBuilder = OpenSshCertificateBuilder.userCertificate();
        openSshCertificateBuilder.provider(issuerProvider);
        openSshCertificateBuilder.id(UUID.randomUUID().toString());
        openSshCertificateBuilder.serial(System.currentTimeMillis());
        openSshCertificateBuilder.extensions(Arrays.asList(
                new OpenSshCertificate.CertificateOption("permit-user-rc"),
                new OpenSshCertificate.CertificateOption("permit-X11-forwarding"),
                new OpenSshCertificate.CertificateOption("permit-agent-forwarding"),
                new OpenSshCertificate.CertificateOption("permit-port-forwarding"),
                new OpenSshCertificate.CertificateOption("permit-pty")));
        openSshCertificateBuilder.principals(List.of(username));
        openSshCertificateBuilder.publicKey(publicKey);
        openSshCertificateBuilder.validAfter(notBefore.toInstant());
        openSshCertificateBuilder.validBefore(notAfter.toInstant());
        return openSshCertificateBuilder.sign(new KeyPair(issuerPublicKey, issuerPrivateKey), org.apache.sshd.common.config.keys.KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS);
    }

}
