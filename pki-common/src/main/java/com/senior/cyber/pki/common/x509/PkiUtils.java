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
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

/**
 * CSCA: Country Signing Certification Authority
 * ICAO: International Civil Aviation Organization. They publish the e-passport spec (Doc 9303) and run the global key-sharing service (PKD).
 * PKD: Public Key Directory, ICAO’s clearinghouse where countries upload/share their CSCA certs, link certs, CRLs, and often DSCs/Master Lists. Border systems sync from PKD (and/or bilateral exchanges) to know which keys to trust.
 * DSC: Document Signer Certificate
 * MRZ: Machine Readable Zone
 * LDS Security Object: " The ASN.1 structure inside EF.SOD that holds: a version, the digest algorithm, and the list of (DG number → DG hash) pairs. (LDS = Logical Data Structure—the standardized file layout on the chip: EF.COM, DG1, DG2, …)
 * KU: Key Usage
 * EKU: Extended Key Usage
 * LDS: Logical Data Structure.
 * DG1 — MRZ data (exact copy of the printed MRZ). Required.
 * DG2 — Encoded facial image (JPEG/JPEG2000/updated biometrics format). Required.
 * DG3 — Fingerprint(s) (if a state uses them). Optional.
 * DG4 — Iris image(s) (if used). Optional.
 * DG5 — Displayed portrait (scan of the printed photo on the data page). Optional.
 * DG6 — Reserved for future use (no defined content in Doc 9303). Optional.
 * DG7 — Displayed signature or usual mark (image of the holder’s signature/mark). Optional.
 * DG8 — Data feature(s) (slot for additional facial features/encodings; rarely used). Optional.
 * DG9 — Structure feature(s) (historically reserved; Doc 9303 leaves this undefined / proprietary). Optional.
 * DG10 — Substance feature(s) (historically reserved; undefined in Doc 9303). Optional.
 * DG11 — Additional personal details (e.g., full name in national script, place of birth, etc.). Optional.
 * DG12 — Additional document details (e.g., issuing authority, issue date). Optional.
 * DG13 — Optional details (issuer-specific). Optional.
 * DG14 — Security options / Chip Authentication public key & metadata. Conditional.
 * DG15 — Active Authentication public key info. Conditional.
 * DG16 — Person(s) to notify (emergency contact). Optional.
 */
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
     * @param ca                is ca
     * @param notBefore         Date
     * @param notAfter          Date
     * @param serial            serial
     * @param keyUsages         keyUsages
     * @param extendedKeyUsages extendedKeyUsages
     * @param sans              Subject Alternative Name (IP, DNS)
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
     * @param issuerProvider    issuerProvider
     * @param issuerPrivateKey  issuerPrivateKey
     * @param issuerCertificate issuerCertificate
     * @param crl               URI of crl repository, crl repository have to be signed by CRL Certificate which sign by certificate issuer (*.crl)
     * @param ocsp              URI of ocsp request/response signer, the OCSP certificate which sign by certificate issuer
     * @param caIssuer          URI of the issuer certificate file (*.der)
     * @param publicKey         public key which issuer want to sign
     * @param subject           subject which issuer want to sign
     * @param pathLenConstraint pathLenConstraint
     * @param notBefore         Date
     * @param notAfter          Date
     * @param serial            serial
     * @param keyUsages         keyUsages
     * @param extendedKeyUsages extendedKeyUsages
     * @param sans              Subject Alternative Name (IP, DNS)
     * @return a signed certificate which signed by issuerPrivateKey
     */
    public static X509Certificate issue(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate,
                                        String crl, String ocsp, String caIssuer, String crlIssuer,
                                        PublicKey publicKey, X500Name subject,
                                        int pathLenConstraint, Date notBefore, Date notAfter, long serial,
                                        List<Integer> keyUsages,
                                        List<KeyPurposeId> extendedKeyUsages,
                                        List<String> sans) throws CertIOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        X500Name issuerSubject = X500Name.getInstance(issuerCertificate.getSubjectX500Principal().getEncoded());
        PublicKey issuerPublicKey = issuerCertificate.getPublicKey();
        return issue(issuerProvider, issuerPrivateKey, issuerPublicKey, issuerSubject, crl, ocsp, caIssuer, crlIssuer, publicKey, subject, pathLenConstraint, notBefore, notAfter, serial, keyUsages, extendedKeyUsages, sans);
    }

    /**
     * @param issuerProvider    issuerProvider
     * @param issuerPrivateKey  issuerPrivateKey
     * @param issuerPublicKey   issuerPublicKey
     * @param issuerSubject     issuerSubject
     * @param crl               URI of crl repository, crl repository have to be signed by CRL Certificate which sign by certificate issuer (*.crl)
     * @param ocsp              URI of ocsp request/response signer, the OCSP certificate which sign by certificate issuer
     * @param caIssuer          URI of the issuer certificate file (*.der)
     * @param crlIssuer         TODO
     * @param publicKey         public key which issuer want to sign
     * @param subject           subject which issuer want to sign
     * @param ca                is ca
     * @param notBefore         Date
     * @param notAfter          Date
     * @param serial            serial
     * @param keyUsages         keyUsages
     * @param extendedKeyUsages extendedKeyUsages
     * @param sans              Subject Alternative Name (IP, DNS)
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
        return internalIssue(utils, builder, issuerProvider, issuerPrivateKey, issuerPublicKey, crl, ocsp, caIssuer, crlIssuer, publicKey, keyUsages, extendedKeyUsages, sans);
    }

    /**
     * @param issuerProvider    issuerProvider
     * @param issuerPrivateKey  issuerPrivateKey
     * @param issuerPublicKey   issuerPublicKey
     * @param issuerSubject     issuerSubject
     * @param crl               URI of crl repository, crl repository have to be signed by CRL Certificate which sign by certificate issuer (*.crl)
     * @param ocsp              URI of ocsp request/response signer, the OCSP certificate which sign by certificate issuer
     * @param caIssuer          URI of the issuer certificate file (*.der)
     * @param crlIssuer         TODO
     * @param publicKey         public key which issuer want to sign
     * @param subject           subject which issuer want to sign
     * @param pathLenConstraint pathLenConstraint
     * @param notBefore         Date
     * @param notAfter          Date
     * @param serial            serial
     * @param keyUsages         keyUsages
     * @param extendedKeyUsages extendedKeyUsages
     * @param sans              Subject Alternative Name (IP, DNS)
     * @return a signed certificate which signed by issuerPrivateKey
     */
    public static X509Certificate issue(Provider issuerProvider, PrivateKey issuerPrivateKey, PublicKey issuerPublicKey, X500Name issuerSubject,
                                        String crl, String ocsp, String caIssuer, String crlIssuer,
                                        PublicKey publicKey, X500Name subject,
                                        int pathLenConstraint, Date notBefore, Date notAfter, long serial,
                                        List<Integer> keyUsages,
                                        List<KeyPurposeId> extendedKeyUsages,
                                        List<String> sans) throws CertIOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerSubject, BigInteger.valueOf(serial), notBefore, notAfter, subject, publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLenConstraint));
        return internalIssue(utils, builder, issuerProvider, issuerPrivateKey, issuerPublicKey, crl, ocsp, caIssuer, crlIssuer, publicKey, keyUsages, extendedKeyUsages, sans);
    }

    private static X509Certificate internalIssue(JcaX509ExtensionUtils utils, JcaX509v3CertificateBuilder builder, Provider issuerProvider, PrivateKey issuerPrivateKey, PublicKey issuerPublicKey,
                                                 String crl, String ocsp, String caIssuer, String crlIssuer,
                                                 PublicKey publicKey,
                                                 List<Integer> keyUsages,
                                                 List<KeyPurposeId> extendedKeyUsages,
                                                 List<String> sans) throws CertIOException, OperatorCreationException, CertificateException {
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
        if (issuerPrivateKey instanceof RSAKey) {
            format = "RSA";
        } else if (issuerPrivateKey instanceof ECKey || "EC".equals(issuerPrivateKey.getAlgorithm())) {
            format = "ECDSA";
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

    public static X509Certificate issueRootCa(Provider issuerProvider, PrivateKey privateKey, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        List<Integer> keyUsages = Arrays.asList(KeyUsage.cRLSign, KeyUsage.keyCertSign);
        return issue(issuerProvider, privateKey, publicKey, subject, null, null, null, null, publicKey, subject, true, notBefore, notAfter, serial, keyUsages, null, null);
    }

    public static X509Certificate issueSshCaCertificate(Provider issuerProvider, RSAPrivateKey privateKey, RSAPublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        List<Integer> keyUsages = Arrays.asList(KeyUsage.cRLSign, KeyUsage.keyCertSign);
        return issue(issuerProvider, privateKey, publicKey, subject, null, null, null, null, publicKey, subject, true, notBefore, notAfter, serial, keyUsages, null, null);
    }

    public static X509Certificate issueIssuingCa(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate, String crl, String ocsp, String caIssuer, String crlIssuer, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        List<Integer> keyUsages = Arrays.asList(KeyUsage.cRLSign, KeyUsage.keyCertSign);
        return issue(issuerProvider, issuerPrivateKey, issuerCertificate, crl, ocsp, caIssuer, crlIssuer, publicKey, subject, 0, notBefore, notAfter, serial, keyUsages, null, null);
    }

    /**
     * Subordinate CA (SubCA)     *
     * Any CA that is not the Root CA.     *
     * Issued by another CA (either the Root or another SubCA).     *
     * Can be used for multiple purposes, depending on its certificate extensions and policies:     *
     * Intermediate CA: may sign other SubCAs.     *
     * Issuing CA: may issue end-entity (leaf) certificates.     *
     * It’s a broad category — includes both intermediates and issuers.
     *
     * @param issuerProvider
     * @param issuerPrivateKey
     * @param issuerCertificate
     * @param crl
     * @param ocsp
     * @param caIssuer
     * @param crlIssuer
     * @param publicKey
     * @param subject
     * @param notBefore
     * @param notAfter
     * @param serial
     * @return
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws OperatorCreationException
     * @throws CertIOException
     */
    public static X509Certificate issueSubordinateCA(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate, String crl, String ocsp, String caIssuer, String crlIssuer, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        List<Integer> keyUsages = Arrays.asList(KeyUsage.cRLSign, KeyUsage.keyCertSign);
        // 1 - meaning allow this certificate to issue 1 sub-level ca
        int pathLenConstraint = 1;
        return issue(issuerProvider, issuerPrivateKey, issuerCertificate, crl, ocsp, caIssuer, crlIssuer, publicKey, subject, pathLenConstraint, notBefore, notAfter, serial, keyUsages, null, null);
    }

    public static X509Certificate mtlsServerCertificate(Provider issuerProvider, PrivateKey privateKey, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        List<Integer> keyUsages = Arrays.asList(KeyUsage.cRLSign, KeyUsage.keyCertSign);
        // 0 - this certificate can sign only leaf
        int pathLenConstraint = 0;
        return issue(issuerProvider, privateKey, publicKey, subject, null, null, null, null, publicKey, subject, pathLenConstraint, notBefore, notAfter, serial, keyUsages, null, null);
    }

    public static CrossSignRoot issueCrossSignRootCertificate(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate, String crl, String ocsp, String caIssuer, String crlIssuer, Provider provider, PrivateKey privateKey, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        X509Certificate root = issueRootCa(provider, privateKey, publicKey, subject, notBefore, notAfter, serial);
        X509Certificate crossRoot = issueSubordinateCA(issuerProvider, issuerPrivateKey, issuerCertificate, crl, ocsp, caIssuer, crlIssuer, publicKey, subject, notBefore, notAfter, serial + 1);
        return new CrossSignRoot(root, crossRoot);
    }

    public static X509Certificate issueLeafCertificate(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate, String crl, String ocsp, String caIssuer, String crlIssuer, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial, List<Integer> keyUsages, List<KeyPurposeId> extendedKeyUsages, List<String> sans) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        return issue(issuerProvider, issuerPrivateKey, issuerCertificate, crl, ocsp, caIssuer, crlIssuer, publicKey, subject, false, notBefore, notAfter, serial, keyUsages, extendedKeyUsages, sans);
    }

    public static X509Certificate issueCrlCertificate(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        List<Integer> keyUsages = List.of(KeyUsage.cRLSign);
        return issueLeafCertificate(issuerProvider, issuerPrivateKey, issuerCertificate, null, null, null, null, publicKey, subject, notBefore, notAfter, serial, keyUsages, null, null);
    }

    public static X509Certificate issueOcspCertificate(Provider issuerProvider, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate, PublicKey publicKey, X500Name subject, Date notBefore, Date notAfter, long serial) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, CertIOException {
        List<Integer> keyUsages = List.of(KeyUsage.digitalSignature);
        List<KeyPurposeId> extendedKeyUsages = List.of(KeyPurposeId.id_kp_OCSPSigning);
        return issueLeafCertificate(issuerProvider, issuerPrivateKey, issuerCertificate, null, null, null, null, publicKey, subject, notBefore, notAfter, serial, keyUsages, extendedKeyUsages, null);
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
