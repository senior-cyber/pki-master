package com.senior.cyber.pki.web.utility;

import com.senior.cyber.pki.web.dto.CsrDto;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public class CertificationSignRequestUtility {

    public static PKCS10CertificationRequest generate(PrivateKey privateKey, PublicKey publicKey, X500Name subject) throws OperatorCreationException {
        return generate(privateKey, publicKey, subject, 256);
    }

    public static PKCS10CertificationRequest generate(PrivateKey privateKey, PublicKey publicKey, X500Name subject, int keySize) throws OperatorCreationException {
        String format = "";
        if (publicKey instanceof RSAPublicKey) {
            format = "RSA";
        } else if (publicKey instanceof ECPublicKey) {
            format = "ECDSA";
        } else if (publicKey instanceof DSAPublicKey) {
            format = "DSA";
        }
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA" + keySize + "WITH" + format);
        csBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner contentSigner = csBuilder.build(privateKey);
        return builder.build(contentSigner);
    }

    public static CsrDto readCsr(PKCS10CertificationRequest csr) {

        X500Name subject = csr.getSubject();

        String countryCode = null;
        String organization = null;
        String organizationalUnit = null;
        String commonName = null;
        String localityName = null;
        String stateOrProvinceName = null;
        String emailAddress = null;

        for (RDN rdn : subject.getRDNs()) {
            AttributeTypeAndValue first = rdn.getFirst();
            if (first != null) {
                ASN1Encodable value = first.getValue();
                if (value != null) {
                    ASN1Primitive primitive = value.toASN1Primitive();
                    if (primitive != null) {
                        String text = null;
                        if (primitive instanceof ASN1String) {
                            text = ((ASN1String) primitive).getString();
                        }
                        ASN1ObjectIdentifier type = first.getType();
                        if (BCStyle.C.equals(type)) {
                            countryCode = text;
                        } else if (BCStyle.O.equals(type)) {
                            organization = text;
                        } else if (BCStyle.OU.equals(type)) {
                            organizationalUnit = text;
                        } else if (BCStyle.CN.equals(type)) {
                            commonName = text;
                        } else if (BCStyle.L.equals(type)) {
                            localityName = text;
                        } else if (BCStyle.ST.equals(type)) {
                            stateOrProvinceName = text;
                        } else if (BCStyle.EmailAddress.equals(type)) {
                            emailAddress = text;
                        }
                    }
                }
            }
        }

        CsrDto dto = new CsrDto();
        dto.setCountryCode(countryCode);
        dto.setOrganization(organization);
        dto.setOrganizationalUnit(organizationalUnit);
        dto.setCommonName(commonName);
        dto.setLocalityName(localityName);
        dto.setStateOrProvinceName(stateOrProvinceName);
        dto.setEmailAddress(emailAddress);
        return dto;
    }

}
