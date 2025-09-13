package com.senior.cyber.pki.client.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.common.x509.*;
import org.apache.commons.io.FileUtils;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;

@SpringBootApplication
public class ClientProgram implements CommandLineRunner {

//    private static final String KEY = "https://pki-api-key.khmer.name";
//    private static final String ROOT = "https://pki-api-root.khmer.name";
//    private static final String ISSUER = "https://pki-api-issuer.khmer.name";
//    private static final String SSH = "https://pki-api-ssh.khmer.name";
//    private static final String X509 = "https://pki-api-x509.khmer.name";

    private static final String KEY = "http://127.0.0.1:3103";
    private static final String ROOT = "http://127.0.0.1:3102";
    private static final String ISSUER = "http://127.0.0.1:3101";
    private static final String SSH = "http://127.0.0.1:3004";
    private static final String X509 = "http://127.0.0.1:3003";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void main(String[] args) {
        SpringApplication.run(ClientProgram.class, args);
    }

    @Override
    public void run(String... args) throws IOException, InterruptedException {
//        x509(args);
//        System.out.println("Done x509");
        mtls(args);
        System.out.println("Done mtls");
//        sshCa(args);
//        System.out.println("Done ssh-ca");
        System.exit(0);
    }

    public KeyGenerateResponse sshCa(String... args) throws IOException, InterruptedException {
        KeyGenerateResponse sshCaKey = generateYubicoKey("9a");
        System.out.println(SSH + "/api/openssh/" + sshCaKey.getKeyId() + ".pub");

        KeyGenerateResponse sshClientKey = generateYubicoKey("9c");
        System.out.println(SSH + "/api/openssh/" + sshClientKey.getKeyId() + ".pub");
        SshClientGenerateResponse sshClient = generateSshClient(sshCaKey, sshClientKey, "socheat", "192.168.1.53", 1000);
        System.out.println(sshClient.getConfig());
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/ssh-ca.pem"), OpenSshPublicKeyUtils.convert(sshCaKey.getOpensshPublicKey()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/ssh-client-id_rsa"), OpenSshPrivateKeyUtils.convert(sshClient.getPrivateKey()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/ssh-client-id_rsa.pub"), OpenSshPublicKeyUtils.convert(sshClient.getPublicKey()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/ssh-client-id_rsa-cert.pub"), OpenSshCertificateUtils.convert(sshClient.getCertificate()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/ssh-client-config"), sshClient.getConfig());
        return sshCaKey;
    }

    public void mtls(String... args) throws IOException, InterruptedException {
        KeyGenerateResponse mtlsServerKey = generateYubicoKey("9a");
        System.out.println(SSH + "/api/openssh/" + mtlsServerKey.getKeyId() + ".pub");
        MtlsGenerateResponse mtlsServer = generateMtlsServer(mtlsServerKey, "Phnom Penh", "Kandal", "KH", "mTLS Server", "Ministry of Post and Telecommunications", "Digital Government Committee");
        System.out.println(X509 + "/api/x509/" + String.format("%012X", mtlsServer.getCertificate().getSerialNumber()) + ".crt");

        KeyGenerateResponse mtlsClientKey = generateYubicoKey("9c");
        System.out.println(SSH + "/api/openssh/" + mtlsClientKey.getKeyId() + ".pub");
        MtlsClientGenerateResponse mtlsClient = generateMtlsClient(mtlsServer, mtlsClientKey, "Phnom Penh", "Kandal", "KH", "mTLS Client", "Ministry of Post and Telecommunications", "Digital Government Committee");
        System.out.println(X509 + "/api/x509/" + String.format("%012X", mtlsClient.getCert().getSerialNumber()) + ".crt");

        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/pki-mtls-server.pem"), CertificateUtils.convert(mtlsServer.getCertificate()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/pki-mtls-client-cert.pem"), CertificateUtils.convert(mtlsClient.getCert()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/pki-mtls-client-privkey.pem"), PrivateKeyUtils.convert(mtlsClient.getPrivkey()));
    }

    public void x509(String... args) throws IOException, InterruptedException {
        KeyGenerateResponse rootCaKey = generateYubicoKey("9a");
        System.out.println(SSH + "/api/openssh/" + rootCaKey.getKeyId() + ".pub");
        RootGenerateResponse rootCa = generateRootCA(rootCaKey, "Phnom Penh", "Kandal", "KH", "Cambodia National RootCA", "Ministry of Post and Telecommunications", "Digital Government Committee");
        System.out.println(X509 + "/api/x509/" + String.format("%012X", rootCa.getCertificate().getSerialNumber()) + ".crt");

        KeyGenerateResponse subordinateCaKey = generateYubicoKey("9c");
        System.out.println(SSH + "/api/openssh/" + subordinateCaKey.getKeyId() + ".pub");
        SubordinateGenerateResponse subordinateCa = generateSubordinateCA(rootCa, subordinateCaKey, "Phnom Penh", "Kandal", "KH", "Cambodia National SubordinateCA", "Ministry of Post and Telecommunications", "Digital Government Committee");
        System.out.println(X509 + "/api/x509/" + String.format("%012X", subordinateCa.getCertificate().getSerialNumber()) + ".crt");

        KeyGenerateResponse issuingCaKey1 = generateYubicoKey("9d");
        System.out.println(SSH + "/api/openssh/" + issuingCaKey1.getKeyId() + ".pub");
        IssuerGenerateResponse issuingCa1 = generateIssuingCA(rootCa, issuingCaKey1, "Phnom Penh", "Kandal", "KH", "Cambodia National IssuingCA", "Ministry of Post and Telecommunications", "Digital Government Committee");
        System.out.println(X509 + "/api/x509/" + String.format("%012X", issuingCa1.getCertificate().getSerialNumber()) + ".crt");

        KeyGenerateResponse issuingCaKey2 = generateJcaKey();
        System.out.println(SSH + "/api/openssh/" + issuingCaKey2.getKeyId() + ".pub");
        IssuerGenerateResponse issuingCa2 = generateIssuingCA(subordinateCa, issuingCaKey2, "Phnom Penh", "Kandal", "KH", "Cambodia National IssuingCA", "Ministry of Post and Telecommunications", "Digital Government Committee");
        System.out.println(X509 + "/api/x509/" + String.format("%012X", issuingCa2.getCertificate().getSerialNumber()) + ".crt");

        KeyGenerateResponse serverKey = generateYubicoKey("9a");
        System.out.println(SSH + "/api/openssh/" + serverKey.getKeyId() + ".pub");
        ServerGenerateResponse server = generateServer(issuingCa2, serverKey, "Phnom Penh", "Kandal", "KH", "127.0.0.1", "Ministry of Post and Telecommunications", "Digital Government Committee", List.of("127.0.0.1", "localhost"));
        System.out.println(X509 + "/api/x509/" + String.format("%012X", server.getCert().getSerialNumber()) + ".crt");

        FileUtils.write(new File("/opt/apps/tls/root-ca.pem"), CertificateUtils.convert(rootCa.getCertificate()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/fullchain.pem"), CertificateUtils.convert(server.getFullchain()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/privkey.pem"), PrivateKeyUtils.convert(server.getPrivkey()));
    }

    protected static SshClientGenerateResponse generateSshClient(KeyGenerateResponse issuer, KeyGenerateResponse key, String principal, String server, long validityPeriod) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            SshClientGenerateRequest request = new SshClientGenerateRequest();
            request.setIssuer(new Issuer(null, issuer.getKeyId(), issuer.getKeyPassword()));
            request.setKeyId(key.getKeyId());
            request.setKeyPassword(key.getKeyPassword());
            request.setPrincipal(principal);
            request.setServer(server);
            request.setAlias("test");
            request.setValidityPeriod(validityPeriod);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(ISSUER + "/api/ssh/client/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), SshClientGenerateResponse.class);
        }
    }

    protected static KeyGenerateResponse generateJcaKey() throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            JcaKeyGenerateRequest request = new JcaKeyGenerateRequest();
            request.setSize(2048);
            request.setFormat(KeyFormat.RSA);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(KEY + "/api/jca/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), KeyGenerateResponse.class);
        }
    }

    protected static KeyGenerateResponse registerYubicoKey(String slot) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            YubicoKeyRegisterRequest request = new YubicoKeyRegisterRequest();
            request.setSerialNumber("23275988");
            request.setSlot(slot);
            request.setManagementKey("010203040506070801020304050607080102030405060708");
            request.setPin("123456");

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(KEY + "/api/yubico/register"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), KeyGenerateResponse.class);
        }
    }

    protected static KeyGenerateResponse generateYubicoKey(String slot) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            YubicoKeyGenerateRequest request = new YubicoKeyGenerateRequest();
            request.setSerialNumber("23275988");
            request.setSlot(slot);
            request.setManagementKey("010203040506070801020304050607080102030405060708");
            request.setSize(2048);
            request.setFormat(KeyFormat.RSA);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(KEY + "/api/yubico/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), KeyGenerateResponse.class);
        }
    }

    protected static MtlsClientGenerateResponse generateMtlsClient(MtlsGenerateResponse issuer, KeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            MtlsClientGenerateRequest request = new MtlsClientGenerateRequest();
            request.setIssuer(new Issuer(issuer.getCertificateId(), null, issuer.getKeyPassword()));
            request.setKeyId(key.getKeyId());
            request.setKeyPassword(key.getKeyPassword());
            request.setKeyPassword(key.getKeyPassword());
            request.setLocality(locality);
            request.setProvince(province);
            request.setCountry(country);
            request.setOrganization(o);
            request.setOrganizationalUnit(ou);
            request.setCommonName(cn);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(ISSUER + "/api/mtls/client/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), MtlsClientGenerateResponse.class);
        }
    }

    protected static MtlsGenerateResponse generateMtlsServer(KeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            MtlsGenerateRequest request = new MtlsGenerateRequest();
            request.setKeyId(key.getKeyId());
            request.setKeyPassword(key.getKeyPassword());
            request.setLocality(locality);
            request.setProvince(province);
            request.setCountry(country);
            request.setOrganization(o);
            request.setOrganizationalUnit(ou);
            request.setCommonName(cn);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(ISSUER + "/api/mtls/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), MtlsGenerateResponse.class);
        }
    }

    protected static ServerGenerateResponse generateServer(IssuerGenerateResponse issuer, KeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou, List<String> sans) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            ServerGenerateRequest request = new ServerGenerateRequest();
            request.setIssuer(new Issuer(issuer.getCertificateId(), null, issuer.getKeyPassword()));
            request.setKeyId(key.getKeyId());
            request.setKeyPassword(key.getKeyPassword());
            request.setLocality(locality);
            request.setProvince(province);
            request.setCountry(country);
            request.setOrganization(o);
            request.setOrganizationalUnit(ou);
            request.setCommonName(cn);
            request.setSans(sans);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(ISSUER + "/api/server/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), ServerGenerateResponse.class);
        }
    }

    protected static IssuerGenerateResponse generateIssuingCA(RootGenerateResponse issuer, KeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            IssuerGenerateRequest request = new IssuerGenerateRequest();
            request.setIssuer(new Issuer(issuer.getCertificateId(), null, issuer.getKeyPassword()));
            request.setKeyId(key.getKeyId());
            request.setKeyPassword(key.getKeyPassword());
            request.setLocality(locality);
            request.setProvince(province);
            request.setCountry(country);
            request.setOrganization(o);
            request.setOrganizationalUnit(ou);
            request.setCommonName(cn);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(ROOT + "/api/issuer/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), IssuerGenerateResponse.class);
        }
    }

    protected static IssuerGenerateResponse generateIssuingCA(SubordinateGenerateResponse issuer, KeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            IssuerGenerateRequest request = new IssuerGenerateRequest();
            request.setIssuer(new Issuer(issuer.getCertificateId(), null, issuer.getKeyPassword()));
            request.setKeyId(key.getKeyId());
            request.setKeyPassword(key.getKeyPassword());
            request.setLocality(locality);
            request.setProvince(province);
            request.setCountry(country);
            request.setOrganization(o);
            request.setOrganizationalUnit(ou);
            request.setCommonName(cn);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(ISSUER + "/api/issuer/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), IssuerGenerateResponse.class);
        }
    }

    protected static SubordinateGenerateResponse generateSubordinateCA(RootGenerateResponse issuer, KeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            SubordinateGenerateRequest request = new SubordinateGenerateRequest();
            request.setIssuer(new Issuer(issuer.getCertificateId(), null, issuer.getKeyPassword()));
            request.setKeyId(key.getKeyId());
            request.setKeyPassword(key.getKeyPassword());
            request.setLocality(locality);
            request.setProvince(province);
            request.setCountry(country);
            request.setOrganization(o);
            request.setOrganizationalUnit(ou);
            request.setCommonName(cn);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(ROOT + "/api/subordinate/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), SubordinateGenerateResponse.class);
        }
    }

    protected static RootGenerateResponse generateRootCA(KeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            RootGenerateRequest request = new RootGenerateRequest();
            request.setKeyId(key.getKeyId());
            request.setKeyPassword(key.getKeyPassword());
            request.setLocality(locality);
            request.setProvince(province);
            request.setCountry(country);
            request.setOrganization(o);
            request.setOrganizationalUnit(ou);
            request.setCommonName(cn);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(ROOT + "/api/root/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), RootGenerateResponse.class);
        }
    }

}
