package com.senior.cyber.pki.common.x509;

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

public class IssuerUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static X509Certificate generate(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, String crlApi, String aiaApi) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException {
        return generate(issuerCertificate, issuerKey, csr, crlApi, aiaApi, System.currentTimeMillis());
    }

    public static X509Certificate generate(X509Certificate issuerCertificate, PrivateKey issuerKey, PKCS10CertificationRequest csr, String crlApi, String aiaApi, long serial) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException {
        BigInteger _serial = BigInteger.valueOf(serial);

        boolean basicConstraintsCritical = true;
        boolean keyUsageCritical = true;
        boolean basicConstraints = true;

        boolean subjectKeyIdentifierCritical = false;
        boolean authorityKeyIdentifierCritical = false;
        boolean extendedKeyUsageCritical = false;
        boolean crlDistributionPointsCritical = false;
        boolean authorityInfoAccessCritical = false;
        boolean subjectAlternativeNameCritical = false;

        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = LocalDate.now().plusYears(5).toDate();

        PublicKey subjectPublicKey = new JcaPEMKeyConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getPublicKey(csr.getSubjectPublicKeyInfo());

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerCertificate, _serial, notBefore, notAfter, csr.getSubject(), subjectPublicKey);
        builder.addExtension(Extension.authorityKeyIdentifier, authorityKeyIdentifierCritical, utils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));

        builder.addExtension(Extension.subjectKeyIdentifier, subjectKeyIdentifierCritical, utils.createSubjectKeyIdentifier(subjectPublicKey));
        builder.addExtension(Extension.basicConstraints, basicConstraintsCritical, new BasicConstraints(basicConstraints));
        builder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.cRLSign | KeyUsage.keyCertSign));
        builder.addExtension(Extension.extendedKeyUsage, extendedKeyUsageCritical, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));

        if (crlApi != null && !crlApi.isEmpty()) {
            List<DistributionPoint> distributionPoints = new ArrayList<>();
            distributionPoints.add(new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlApi + "/crl/" + issuerCertificate.getSerialNumber().intValueExact() + ".crl"))), null, null));
            builder.addExtension(Extension.cRLDistributionPoints, crlDistributionPointsCritical, new CRLDistPoint(distributionPoints.toArray(new DistributionPoint[0])));
        }
        if (aiaApi != null && !aiaApi.isEmpty()) {
            List<AccessDescription> accessDescriptions = new ArrayList<>();
            accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, aiaApi + "/ocsp/" + issuerCertificate.getSerialNumber().intValueExact())));
            accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, aiaApi + "/x509/" + issuerCertificate.getSerialNumber().intValueExact() + ".der")));
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

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(holder);
    }

}
