package com.senior.cyber.pki.web.utility;

import com.senior.cyber.pki.web.dto.CertificateRequestDto;
import com.senior.cyber.pki.web.dto.GeneralNameDto;
import com.senior.cyber.pki.web.dto.GeneralNameTypeEnum;
import org.bouncycastle.asn1.x500.X500Name;
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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class CertificateUtility {

    public static X509Certificate generate(CertificateRequestDto requestDto) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException {
        PKCS10CertificationRequest csr = requestDto.getCsr();

        BigInteger serial = null;
        if (requestDto.getSerial() == null) {
            serial = BigInteger.valueOf(System.currentTimeMillis());
        } else {
            serial = BigInteger.valueOf(requestDto.getSerial());
        }

        boolean basicConstraintsCritical = requestDto.isBasicConstraintsCritical();
        boolean subjectKeyIdentifierCritical = requestDto.isSubjectKeyIdentifierCritical();
        boolean authorityKeyIdentifierCritical = requestDto.isAuthorityKeyIdentifierCritical();
        boolean keyUsageCritical = requestDto.isKeyUsageCritical();
        boolean extendedKeyUsageCritical = requestDto.isExtendedKeyUsageCritical();
        boolean cRLDistributionPointsCritical = requestDto.iscRLDistributionPointsCritical();
        boolean authorityInfoAccessCritical = requestDto.isAuthorityInfoAccessCritical();
        boolean subjectAlternativeNameCritical = requestDto.isSubjectAlternativeNameCritical();

        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        Date notBefore = LocalDate.now().toDate();
        Date notAfter = null;
        if (requestDto.getDuration() != null) {
            notAfter = LocalDate.now().plusDays(requestDto.getDuration()).toDate();
        } else {
            if (requestDto.getIssuerCertificate() == null) {
                notAfter = LocalDate.now().plusYears(10).toDate();
            } else {
                if (requestDto.isBasicConstraints()) {
                    notAfter = LocalDate.now().plusYears(5).toDate();
                } else {
                    notAfter = LocalDate.now().plusYears(1).toDate();
                }
            }
        }

        PublicKey subjectPublicKey = new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo());

        JcaX509v3CertificateBuilder builder = null;
        if (requestDto.getIssuerCertificate() == null) {
            // self sign
            X500Name issuerSubject = requestDto.getCsr().getSubject();
            X500Name subject = requestDto.getCsr().getSubject();
            builder = new JcaX509v3CertificateBuilder(issuerSubject, serial, notBefore, notAfter, subject, subjectPublicKey);
            builder.addExtension(Extension.authorityKeyIdentifier, authorityKeyIdentifierCritical, utils.createAuthorityKeyIdentifier(subjectPublicKey));
        } else {
            builder = new JcaX509v3CertificateBuilder(requestDto.getIssuerCertificate(), serial, notBefore, notAfter, requestDto.getCsr().getSubject(), subjectPublicKey);
            builder.addExtension(Extension.authorityKeyIdentifier, authorityKeyIdentifierCritical, utils.createAuthorityKeyIdentifier(requestDto.getIssuerCertificate().getPublicKey()));
        }
        builder.addExtension(Extension.subjectKeyIdentifier, subjectKeyIdentifierCritical, utils.createSubjectKeyIdentifier(subjectPublicKey));

        builder.addExtension(Extension.basicConstraints, basicConstraintsCritical, new BasicConstraints(requestDto.isBasicConstraints()).getEncoded());

        if (requestDto.getKeyUsage() != null && !requestDto.getKeyUsage().isEmpty()) {
            int usage = 0;
            for (com.senior.cyber.pki.web.dto.KeyUsage keyUsage : requestDto.getKeyUsage()) {
                if (com.senior.cyber.pki.web.dto.KeyUsage.digitalSignature == keyUsage) {
                    usage = usage | KeyUsage.digitalSignature;
                } else if (com.senior.cyber.pki.web.dto.KeyUsage.nonRepudiation == keyUsage) {
                    usage = usage | KeyUsage.nonRepudiation;
                } else if (com.senior.cyber.pki.web.dto.KeyUsage.keyEncipherment == keyUsage) {
                    usage = usage | KeyUsage.keyEncipherment;
                } else if (com.senior.cyber.pki.web.dto.KeyUsage.dataEncipherment == keyUsage) {
                    usage = usage | KeyUsage.dataEncipherment;
                } else if (com.senior.cyber.pki.web.dto.KeyUsage.keyAgreement == keyUsage) {
                    usage = usage | KeyUsage.keyAgreement;
                } else if (com.senior.cyber.pki.web.dto.KeyUsage.keyCertSign == keyUsage) {
                    usage = usage | KeyUsage.keyCertSign;
                } else if (com.senior.cyber.pki.web.dto.KeyUsage.cRLSign == keyUsage) {
                    usage = usage | KeyUsage.cRLSign;
                } else if (com.senior.cyber.pki.web.dto.KeyUsage.encipherOnly == keyUsage) {
                    usage = usage | KeyUsage.encipherOnly;
                } else if (com.senior.cyber.pki.web.dto.KeyUsage.decipherOnly == keyUsage) {
                    usage = usage | KeyUsage.decipherOnly;
                }
            }
            if (usage != 0) {
                builder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(usage).getEncoded());
            }
        } else {
            if (requestDto.getIssuerCertificate() == null) {
                builder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.cRLSign | KeyUsage.keyCertSign).getEncoded());
            } else {
                if (requestDto.isBasicConstraints()) {
                    builder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.cRLSign | KeyUsage.keyCertSign).getEncoded());
                } else {
                    builder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement | KeyUsage.dataEncipherment).getEncoded());
                }
            }
        }
        if (requestDto.getExtendedKeyUsage() != null && !requestDto.getExtendedKeyUsage().isEmpty()) {
            List<KeyPurposeId> ids = new ArrayList<>();
            for (com.senior.cyber.pki.web.dto.ExtendedKeyUsage extendedKeyUsage : requestDto.getExtendedKeyUsage()) {
                if (com.senior.cyber.pki.web.dto.ExtendedKeyUsage.anyExtendedKeyUsage == extendedKeyUsage) {
                    ids.add(KeyPurposeId.anyExtendedKeyUsage);
                } else if (com.senior.cyber.pki.web.dto.ExtendedKeyUsage.serverAuth == extendedKeyUsage) {
                    ids.add(KeyPurposeId.id_kp_serverAuth);
                } else if (com.senior.cyber.pki.web.dto.ExtendedKeyUsage.clientAuth == extendedKeyUsage) {
                    ids.add(KeyPurposeId.id_kp_clientAuth);
                } else if (com.senior.cyber.pki.web.dto.ExtendedKeyUsage.codeSigning == extendedKeyUsage) {
                    ids.add(KeyPurposeId.id_kp_codeSigning);
                } else if (com.senior.cyber.pki.web.dto.ExtendedKeyUsage.emailProtection == extendedKeyUsage) {
                    ids.add(KeyPurposeId.id_kp_emailProtection);
                } else if (com.senior.cyber.pki.web.dto.ExtendedKeyUsage.ipsecEndSystem == extendedKeyUsage) {
                    ids.add(KeyPurposeId.id_kp_ipsecEndSystem);
                } else if (com.senior.cyber.pki.web.dto.ExtendedKeyUsage.ipsecTunnel == extendedKeyUsage) {
                    ids.add(KeyPurposeId.id_kp_ipsecTunnel);
                } else if (com.senior.cyber.pki.web.dto.ExtendedKeyUsage.ipsecUser == extendedKeyUsage) {
                    ids.add(KeyPurposeId.id_kp_ipsecUser);
                } else if (com.senior.cyber.pki.web.dto.ExtendedKeyUsage.timeStamping == extendedKeyUsage) {
                    ids.add(KeyPurposeId.id_kp_timeStamping);
                } else if (com.senior.cyber.pki.web.dto.ExtendedKeyUsage.OCSPSigning == extendedKeyUsage) {
                    ids.add(KeyPurposeId.id_kp_OCSPSigning);
                } else if (com.senior.cyber.pki.web.dto.ExtendedKeyUsage.smartCardLogon == extendedKeyUsage) {
                    ids.add(KeyPurposeId.id_kp_smartcardlogon);
                }
            }
            if (!ids.isEmpty()) {
                builder.addExtension(Extension.extendedKeyUsage, extendedKeyUsageCritical, new ExtendedKeyUsage(ids.toArray(new KeyPurposeId[0])).getEncoded());
            }
        } else {
            if (requestDto.getIssuerCertificate() != null) {
                if (requestDto.isBasicConstraints()) {
                    builder.addExtension(Extension.extendedKeyUsage, extendedKeyUsageCritical, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}).getEncoded());
                } else {
                    builder.addExtension(Extension.extendedKeyUsage, extendedKeyUsageCritical, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection}).getEncoded());
                }
            }
        }
        if (requestDto.getCRLDistributionPoints() != null && !requestDto.getCRLDistributionPoints().isEmpty()) {
            List<DistributionPoint> distributionPoints = new ArrayList<>();
            for (GeneralNameDto dto : requestDto.getCRLDistributionPoints()) {
                distributionPoints.add(new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, dto.getName()))), null, null));
            }
            if (!distributionPoints.isEmpty()) {
                builder.addExtension(Extension.cRLDistributionPoints, cRLDistributionPointsCritical, new CRLDistPoint(distributionPoints.toArray(new DistributionPoint[0])).getEncoded());
            }
        }
        if (requestDto.getAuthorityInfoAccess() != null && !requestDto.getAuthorityInfoAccess().isEmpty()) {
            List<AccessDescription> accessDescriptions = new ArrayList<>();
            for (GeneralNameDto dto : requestDto.getAuthorityInfoAccess()) {
                if (GeneralNameTypeEnum.OCSP == dto.getType()) {
                    accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, dto.getName())));
                } else if (GeneralNameTypeEnum.CA == dto.getType()) {
                    accessDescriptions.add(new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, dto.getName())));
                }
            }
            if (!accessDescriptions.isEmpty()) {
                builder.addExtension(Extension.authorityInfoAccess, authorityInfoAccessCritical, new AuthorityInformationAccess(accessDescriptions.toArray(new AccessDescription[0])).getEncoded());
            }
        }
        if (requestDto.getSubjectAlternativeName() != null && !requestDto.getSubjectAlternativeName().isEmpty()) {
            List<GeneralName> generalNames = new ArrayList<>();
            for (GeneralNameDto dto : requestDto.getSubjectAlternativeName()) {
                generalNames.add(new GeneralName(dto.getTag(), dto.getName()));
            }
            if (!generalNames.isEmpty()) {
                GeneralNames subjectAlternativeName = new GeneralNames(generalNames.toArray(new GeneralName[0]));
                builder.addExtension(Extension.subjectAlternativeName, subjectAlternativeNameCritical, subjectAlternativeName.getEncoded());
            }
        }

        PrivateKey issuerPrivateKey = requestDto.getIssuerPrivateKey();
        int keySize = 256;
        String format = "";
        if (issuerPrivateKey instanceof RSAPrivateKey) {
            format = "RSA";
        } else if (issuerPrivateKey instanceof ECPrivateKey) {
            format = "ECDSA";
        } else if (issuerPrivateKey instanceof DSAPrivateKey) {
            format = "DSA";
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA" + keySize + "WITH" + format);
        ContentSigner contentSigner = contentSignerBuilder.build(requestDto.getIssuerPrivateKey());
        X509CertificateHolder holder = builder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(holder);
    }

}
