package com.senior.cyber.pki.common.x509;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

public class CrlUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static boolean validate(X509Certificate certificate, String crlUrl) throws CertificateException, IOException, NoSuchProviderException, CRLException, InterruptedException {
        return validate(certificate, null, crlUrl);
    }

    public static boolean validate(X509Certificate certificate, X509Certificate issuerCertificate, String crlUrl)
            throws IOException, CRLException, InterruptedException, CertificateException, NoSuchProviderException {

        // Step 1: Validate input
        if (certificate == null || crlUrl == null || crlUrl.isBlank()) {
            throw new IllegalArgumentException("Certificate or CRL URL is missing.");
        }

        // Step 2: Fetch CRL data
        try (HttpClient client = HttpClient.newBuilder().build()) {
            HttpRequest request = HttpRequest.newBuilder(URI.create(crlUrl))
                    .GET()
                    .header("Accept", "application/pkix-crl")
                    .build();

            HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200) {
                throw new IOException("Failed to fetch CRL: HTTP status " + response.statusCode());
            }

            byte[] rawCrl = response.body();

            // Step 3: Parse CRL using Bouncy Castle
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            X509CRL crl = (X509CRL) certFactory.generateCRL(new ByteArrayInputStream(rawCrl));

            // Step 4: Optional - Verify the CRL's signature using the issuer certificate
            if (issuerCertificate != null) {
                try {
                    crl.verify(issuerCertificate.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
                } catch (Exception e) {
                    throw new CertificateException("CRL signature verification failed.", e);
                }
            }

            // Step 5: Check if the certificate is revoked
            boolean revoked = crl.isRevoked(certificate);
            if (revoked) {
                System.err.println("Certificate is revoked. Serial: " + certificate.getSerialNumber());
            }

            return !revoked;
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
