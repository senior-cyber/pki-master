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

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void main(String[] args) {
        SpringApplication.run(ClientProgram.class, args);
    }

    @Override
    public void run(String... args) throws IOException, InterruptedException {
        x509(args);
        mtls(args);
        sshCa(args);
        System.exit(0);
    }

    public void sshCa(String... args) throws IOException, InterruptedException {

        SshGenerateResponse sshCaKey = generateSshKey();

        JcaKeyGenerateResponse sshClientKey = generateKey();
        SshClientGenerateResponse sshClient = generateSshClient(sshCaKey, sshClientKey, "socheat", "192.168.1.1", 1000);
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/ssh-ca.pem"), OpenSshPublicKeyUtils.convert(sshCaKey.getSshCa()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/ssh-client-id_rsa"), OpenSshPrivateKeyUtils.convert(sshClient.getPrivateKey()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/ssh-client-id_rsa.pub"), OpenSshPublicKeyUtils.convert(sshClient.getPublicKey()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/ssh-client-id_rsa-cert.pub"), OpenSshCertificateUtils.convert(sshClient.getCertificate()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/ssh-client-config"), sshClient.getOpensshConfig());
    }

    public void mtls(String... args) throws IOException, InterruptedException {
        JcaKeyGenerateResponse mtlsServerKey = generateKey();
        MtlsGenerateResponse mtlsServer = generateMtlsServer(mtlsServerKey, "Phnom Penh", "Kandal", "KH", "mTLS Server", "Ministry of Post and Telecommunications", "Digital Government Committee");
        JcaKeyGenerateResponse mtlsClientKey = generateKey();
        MtlsClientGenerateResponse mtlsClient = generateMtlsClient(mtlsServer, mtlsClientKey, "Phnom Penh", "Kandal", "KH", "mTLS Client", "Ministry of Post and Telecommunications", "Digital Government Committee");
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/pki-mtls-server.pem"), CertificateUtils.convert(mtlsServer.getCertificate()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/pki-mtls-client-cert.pem"), CertificateUtils.convert(mtlsClient.getCert()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/pki-mtls-client-privkey.pem"), PrivateKeyUtils.convert(mtlsClient.getPrivkey()));
    }

    public void x509(String... args) throws IOException, InterruptedException {
        JcaKeyGenerateResponse rootCaKey = generateKey();
        RootGenerateResponse rootCa = generateRootCA(rootCaKey, "Phnom Penh", "Kandal", "KH", "Cambodia National RootCA", "Ministry of Post and Telecommunications", "Digital Government Committee");

        JcaKeyGenerateResponse subordinateCaKey = generateKey();
        SubordinateGenerateResponse subordinateCa = generateSubordinateCA(rootCa, subordinateCaKey, "Phnom Penh", "Kandal", "KH", "Cambodia National SubordinateCA", "Ministry of Post and Telecommunications", "Digital Government Committee");

        JcaKeyGenerateResponse issuingCaKey1 = generateKey();
        IssuerGenerateResponse issuingCa1 = generateIssuingCA(rootCa, issuingCaKey1, "Phnom Penh", "Kandal", "KH", "Cambodia National IssuingCA", "Ministry of Post and Telecommunications", "Digital Government Committee");

        JcaKeyGenerateResponse issuingCaKey2 = generateKey();
        IssuerGenerateResponse issuingCa2 = generateIssuingCA(subordinateCa, issuingCaKey2, "Phnom Penh", "Kandal", "KH", "Cambodia National IssuingCA", "Ministry of Post and Telecommunications", "Digital Government Committee");

        JcaKeyGenerateResponse serverKey = generateKey();
        ServerGenerateResponse server = generateServer(issuingCa2, serverKey, "Phnom Penh", "Kandal", "KH", "127.0.0.1", "Ministry of Post and Telecommunications", "Digital Government Committee", List.of("127.0.0.1", "localhost"));

        FileUtils.write(new File("/opt/apps/tls/root-ca.pem"), CertificateUtils.convert(rootCa.getCertificate()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/fullchain.pem"), CertificateUtils.convert(server.getFullchain()));
        FileUtils.write(new File("/opt/apps/tls/127.0.0.1/privkey.pem"), PrivateKeyUtils.convert(server.getPrivkey()));
    }

    protected static SshClientGenerateResponse generateSshClient(SshGenerateResponse issuer, JcaKeyGenerateResponse key, String principal, String server, long validityPeriod) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            SshClientGenerateRequest request = new SshClientGenerateRequest();
            request.setIssuer(new Issuer(null, issuer.getKeyId(), issuer.getKeyPassword()));
            request.setKeyId(key.getKeyId());
            request.setKeyPassword(key.getKeyPassword());
            request.setPrincipal(principal);
            request.setServer(server);
            request.setValidityPeriod(validityPeriod);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://pki-api-issuer.khmer.name/api/ssh/client/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), SshClientGenerateResponse.class);
        }
    }

    protected static SshGenerateResponse generateSshKey() throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            SshGenerateRequest request = new SshGenerateRequest();
            request.setSize(2048);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://pki-api-issuer.khmer.name/api/ssh/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), SshGenerateResponse.class);
        }
    }

    protected static JcaKeyGenerateResponse generateKey() throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            JcaKeyGenerateRequest request = new JcaKeyGenerateRequest();
            request.setSize(2048);
            request.setFormat(KeyFormat.RSA);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://pki-api-key.khmer.name/api/jca/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), JcaKeyGenerateResponse.class);
        }
    }

    protected static MtlsClientGenerateResponse generateMtlsClient(MtlsGenerateResponse issuer, JcaKeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou) throws IOException, InterruptedException {
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
                    .uri(URI.create("https://pki-api-issuer.khmer.name/api/mtls/client/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), MtlsClientGenerateResponse.class);
        }
    }

    protected static MtlsGenerateResponse generateMtlsServer(JcaKeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            MtlsGenerateRequest request = new MtlsGenerateRequest();
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
                    .uri(URI.create("https://pki-api-issuer.khmer.name/api/mtls/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), MtlsGenerateResponse.class);
        }
    }

    protected static ServerGenerateResponse generateServer(IssuerGenerateResponse issuer, JcaKeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou, List<String> sans) throws IOException, InterruptedException {
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
                    .uri(URI.create("https://pki-api-issuer.khmer.name/api/server/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), ServerGenerateResponse.class);
        }
    }

    protected static IssuerGenerateResponse generateIssuingCA(RootGenerateResponse issuer, JcaKeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou) throws IOException, InterruptedException {
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
                    .uri(URI.create("https://pki-api-root.khmer.name/api/issuer/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), IssuerGenerateResponse.class);
        }
    }

    protected static IssuerGenerateResponse generateIssuingCA(SubordinateGenerateResponse issuer, JcaKeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou) throws IOException, InterruptedException {
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
                    .uri(URI.create("https://pki-api-issuer.khmer.name/api/issuer/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), IssuerGenerateResponse.class);
        }
    }

    protected static SubordinateGenerateResponse generateSubordinateCA(RootGenerateResponse issuer, JcaKeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou) throws IOException, InterruptedException {
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
                    .uri(URI.create("https://pki-api-root.khmer.name/api/subordinate/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), SubordinateGenerateResponse.class);
        }
    }

    protected static RootGenerateResponse generateRootCA(JcaKeyGenerateResponse key, String locality, String province, String country, String cn, String o, String ou) throws IOException, InterruptedException {
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
                    .uri(URI.create("https://pki-api-root.khmer.name/api/root/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), RootGenerateResponse.class);
        }
    }

}
