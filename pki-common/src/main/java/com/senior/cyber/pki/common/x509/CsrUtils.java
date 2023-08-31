package com.senior.cyber.pki.common.x509;

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

import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

public class CsrUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static PKCS10CertificationRequest generate(KeyPair key, X500Name subject) throws OperatorCreationException {
        int shaSize = 256;
        return generate(key, subject, shaSize);
    }

    public static PKCS10CertificationRequest generate(KeyPair key, X500Name subject, int shaSize) throws OperatorCreationException {
        String format = "";
        if (key.getPublic() instanceof RSAPublicKey) {
            format = "RSA";
        } else if (key.getPublic() instanceof ECPublicKey) {
            format = "ECDSA";
        } else if (key.getPublic() instanceof DSAPublicKey) {
            format = "DSA";
        }
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, key.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
        csBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner contentSigner = csBuilder.build(key.getPrivate());
        return builder.build(contentSigner);
    }

    public static Map<ASN1ObjectIdentifier, String> parse(PKCS10CertificationRequest csr) {

        Map<ASN1ObjectIdentifier, String> subject = new HashMap<>();

        X500Name _subject = csr.getSubject();

        for (RDN rdn : _subject.getRDNs()) {
            AttributeTypeAndValue first = rdn.getFirst();
            if (first != null) {
                ASN1Encodable value = first.getValue();
                if (value != null) {
                    ASN1Primitive primitive = value.toASN1Primitive();
                    if (primitive != null) {
                        String text = null;
                        if (primitive instanceof ASN1String asn1String) {
                            text = asn1String.getString();
                        }
                        ASN1ObjectIdentifier type = first.getType();
                        if (BCStyle.C.equals(type)) {
                            subject.put(BCStyle.C, text); // countryCode
                        } else if (BCStyle.O.equals(type)) {
                            subject.put(BCStyle.O, text); // organization
                        } else if (BCStyle.OU.equals(type)) {
                            subject.put(BCStyle.OU, text); // organizationalUnit
                        } else if (BCStyle.CN.equals(type)) {
                            subject.put(BCStyle.CN, text); // commonName
                        } else if (BCStyle.L.equals(type)) {
                            subject.put(BCStyle.L, text); // localityName
                        } else if (BCStyle.ST.equals(type)) {
                            subject.put(BCStyle.ST, text); // stateOrProvinceName
                        } else if (BCStyle.EmailAddress.equals(type)) {
                            subject.put(BCStyle.EmailAddress, text); // emailAddress
                        } else {
                            subject.put(type, text); // unknown
                        }
                    }
                }
            }
        }

        return subject;
    }

}
