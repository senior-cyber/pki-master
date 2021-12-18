package com.senior.cyber.pki.web.utility;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class OcspUtility {

    public static void verifyCertificateWithOcsp(List<X509Certificate> certificates, X509Certificate issuerCert, String ocspUri) throws OCSPException, OperatorCreationException, IOException, CertificateException {
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
        OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        for (X509Certificate certificate : certificates) {
            CertificateID certificateID = new JcaCertificateID(digestCalculatorProvider.get(CertificateID.HASH_SHA1), issuerCert, certificate.getSerialNumber());
            ocspReqBuilder.addRequest(certificateID);
        }
        OCSPReq ocspReq = ocspReqBuilder.build();

        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            ByteArrayEntity entity = new ByteArrayEntity(ocspReq.getEncoded(), ContentType.parse("application/ocsp-request"));
            HttpUriRequest request = RequestBuilder.post().setUri(ocspUri).setEntity(entity).build();
            try (CloseableHttpResponse response = client.execute(request)) {
                byte[] raw = EntityUtils.toByteArray(response.getEntity());
                OCSPResp ocspResponse = new OCSPResp(raw);

                BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResponse.getResponseObject();
                X509CertificateHolder[] certificateHolders = basicOCSPResp.getCerts();
                X509Certificate signerCert = new JcaX509CertificateConverter().getCertificate(certificateHolders[0]);
                JcaContentVerifierProviderBuilder jcaContentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
                ContentVerifierProvider contentVerifierProvider = jcaContentVerifierProviderBuilder.build(signerCert.getPublicKey());
                if (basicOCSPResp.isSignatureValid(contentVerifierProvider)) {
                    SingleResp[] singleResps = basicOCSPResp.getResponses();
                    JcaX509CertificateHolder holder = new JcaX509CertificateHolder(issuerCert);
                    for (SingleResp singleResp : singleResps) {
                        for (X509Certificate cer : certificates) {
                            boolean valid = singleResp.getCertID().matchesIssuer(holder, digestCalculatorProvider) && singleResp.getCertID().getSerialNumber().compareTo((cer).getSerialNumber()) == 0 && singleResp.getCertStatus() == null;
                            System.out.println(valid);
                        }
                    }
                }

            }
        }
    }

    public static List<String> getOcspUrl(X509Certificate certificate) throws IOException {
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
            if (taggedObject != null) {
                ASN1IA5String string = ASN1IA5String.getInstance(taggedObject, false);
                urls.add(string.getString());
            }
        }
        return urls;
    }

}
