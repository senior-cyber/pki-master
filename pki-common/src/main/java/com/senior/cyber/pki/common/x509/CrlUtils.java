package com.senior.cyber.pki.common.x509;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class CrlUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static boolean validate(X509Certificate certificate, String crlUrl) throws IOException, CRLException, InterruptedException {
        try (HttpClient client = HttpClient.newBuilder().build()) {
            HttpRequest request = HttpRequest.newBuilder(URI.create(crlUrl))
                    .GET()
                    .build();
            HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
            byte[] raw = response.body();
            CertificateFactory certificateFactory = new CertificateFactory();
            CRL crl = certificateFactory.engineGenerateCRL(new ByteArrayInputStream(raw));
            return !crl.isRevoked(certificate);
        }
    }

    public static List<String> lookupUrl(X509Certificate certificate) throws IOException {
        byte[] bytes = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (bytes == null) {
            return null;
        }
        ASN1Primitive asn1Primitive = null;
        try (ASN1InputStream asn1Stream = new ASN1InputStream(new ByteArrayInputStream(bytes))) {
            ASN1OctetString asn1Object = (ASN1OctetString) asn1Stream.readObject();
            try (ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(asn1Object.getOctets()))) {
                asn1Primitive = stream.readObject();
            }
        }
        if (asn1Primitive == null) {
            return null;
        }
        List<String> urls = new ArrayList<>();
        CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(asn1Primitive);
        DistributionPoint[] distributionPoints = crlDistPoint.getDistributionPoints();
        for (DistributionPoint distributionPoint : distributionPoints) {
            GeneralNames generalNames = (GeneralNames) distributionPoint.getDistributionPoint().getName();
            for (GeneralName generalName : generalNames.getNames()) {
                DERIA5String string = (DERIA5String) generalName.getName();
                if (string.getString().startsWith("http://") || string.getString().startsWith("https://")) {
                    urls.add(string.getString());
                }
            }
        }
        return urls;
    }

}
