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
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

public class CsrUtils {

    public static PKCS10CertificationRequest generate(KeyPair key, X500Name subject) {
        int shaSize = 256;
        return generate(key, subject, shaSize);
    }

    public static PublicKey lookupPublicKey(PKCS10CertificationRequest csr) {
        Provider provider = new BouncyCastleProvider();
        JcaPEMKeyConverter subjectPublicKeyConverter = new JcaPEMKeyConverter();
        subjectPublicKeyConverter.setProvider(provider);
        PublicKey subjectPublicKey = null;
        try {
            subjectPublicKey = subjectPublicKeyConverter.getPublicKey(csr.getSubjectPublicKeyInfo());
        } catch (PEMException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        return subjectPublicKey;
    }

    public static boolean isValid(PKCS10CertificationRequest csr) {
        Provider provider = new BouncyCastleProvider();
        JcaPEMKeyConverter subjectPublicKeyConverter = new JcaPEMKeyConverter();
        subjectPublicKeyConverter.setProvider(provider);
        PublicKey subjectPublicKey = null;
        try {
            subjectPublicKey = subjectPublicKeyConverter.getPublicKey(csr.getSubjectPublicKeyInfo());
        } catch (PEMException e) {
            return false;
        }

        JcaContentVerifierProviderBuilder verifierBuilder = new JcaContentVerifierProviderBuilder();
        verifierBuilder.setProvider(new BouncyCastleProvider());
        ContentVerifierProvider verifier = null;
        try {
            verifier = verifierBuilder.build(subjectPublicKey);
        } catch (OperatorCreationException e) {
            return false;
        }

        try {
            if (!csr.isSignatureValid(verifier)) {
                return false;
            }
        } catch (PKCSException e) {
            return false;
        }
        return true;
    }

    public static PKCS10CertificationRequest generate(KeyPair key, X500Name subject, int shaSize) {
        String format = "";
        if (key.getPublic() instanceof RSAPublicKey) {
            format = "RSA";
        } else if (key.getPublic() instanceof ECPublicKey || "EC".equals(key.getPublic().getAlgorithm())) {
            format = "ECDSA";
        } else if (key.getPublic() instanceof DSAPublicKey) {
            format = "DSA";
        } else {
            format = key.getPublic().getAlgorithm();
        }

        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, key.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA" + shaSize + "WITH" + format);
        csBuilder.setProvider(new BouncyCastleProvider());
        ContentSigner contentSigner = null;
        try {
            contentSigner = csBuilder.build(key.getPrivate());
        } catch (OperatorCreationException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
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

    public static String convert(PKCS10CertificationRequest value) {
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
            writer.writeObject(value);
        } catch (IOException e) {
            return null;
        }
        return pem.toString();
    }

    public static PKCS10CertificationRequest convert(String value) {
        try (PEMParser parser = new PEMParser(new StringReader(value))) {
            Object object = parser.readObject();
            if (object instanceof PKCS10CertificationRequest holder) {
                return holder;
            } else {
                throw new UnsupportedOperationException(object.getClass().getName());
            }
        } catch (IOException e) {
            return null;
        }
    }

}
