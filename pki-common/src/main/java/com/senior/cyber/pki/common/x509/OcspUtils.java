package com.senior.cyber.pki.common.x509;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class OcspUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static List<String> lookupUrl(X509Certificate certificate) throws IOException {
        byte[] bytes = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
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
        AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(asn1Primitive);
        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        for (AccessDescription accessDescription : accessDescriptions) {
            boolean correctAccessMethod = accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod);
            if (!correctAccessMethod) {
                continue;
            }
            GeneralName name = accessDescription.getAccessLocation();
            if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
                continue;
            }
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) name.toASN1Primitive();
            ASN1IA5String string = DERIA5String.getInstance(taggedObject, false);
            urls.add(string.getString());
        }
        return urls;
    }

    public static boolean validate(X509Certificate certificate, X509Certificate issuerCertificate, String ocspUri)
            throws OCSPException, OperatorCreationException, IOException, CertificateException, InterruptedException {

        // Step 1: Create CertificateID for OCSP request
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build();

        CertificateID certificateID = new JcaCertificateID(
                digestCalculatorProvider.get(CertificateID.HASH_SHA1),
                issuerCertificate,
                certificate.getSerialNumber()
        );

        OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        ocspReqBuilder.addRequest(certificateID);
        OCSPReq ocspReq = ocspReqBuilder.build();

        // Step 2: Send OCSP request to responder
        try (HttpClient client = HttpClient.newBuilder().build()) {
            HttpRequest request = HttpRequest.newBuilder(URI.create(ocspUri))
                    .POST(HttpRequest.BodyPublishers.ofByteArray(ocspReq.getEncoded()))
                    .header("Content-Type", "application/ocsp-request")
                    .build();

            HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
            byte[] raw = response.body();

            // Step 3: Parse and validate OCSP response
            OCSPResp ocspResponse = new OCSPResp(raw);
            if (ocspResponse.getStatus() != OCSPResp.SUCCESSFUL) {
                return false;
            }

            Object responseObject = ocspResponse.getResponseObject();
            if (!(responseObject instanceof BasicOCSPResp basicOCSPResp)) {
                return false;
            }

            // Step 4: Verify OCSP response signature
            X509CertificateHolder[] certHolders = basicOCSPResp.getCerts();
            if (certHolders.length == 0) {
                return false;
            }

            X509Certificate signerCert = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(certHolders[0]);

            ContentVerifierProvider contentVerifier = new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(signerCert.getPublicKey());

            if (!basicOCSPResp.isSignatureValid(contentVerifier)) {
                return false;
            }

            // Step 5: Check OCSP response status for the certificate
            SingleResp[] responses = basicOCSPResp.getResponses();
            if (responses.length == 0) {
                return false;
            }

            SingleResp singleResp = responses[0];

            CertificateID responseCertId = singleResp.getCertID();
            boolean issuerMatch = responseCertId.matchesIssuer(new JcaX509CertificateHolder(issuerCertificate), digestCalculatorProvider);
            boolean serialMatch = responseCertId.getSerialNumber().equals(certificate.getSerialNumber());

            if (!issuerMatch || !serialMatch) {
                return false;
            }

            Object certStatus = singleResp.getCertStatus();
            return certStatus == CertificateStatus.GOOD;
        }
    }

}
