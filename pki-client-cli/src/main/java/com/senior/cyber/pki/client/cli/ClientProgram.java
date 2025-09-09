package com.senior.cyber.pki.client.cli;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.JcaKeyGenerateRequest;
import com.senior.cyber.pki.common.dto.JcaKeyGenerateResponse;
import com.senior.cyber.pki.common.x509.KeyFormat;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@SpringBootApplication
public class ClientProgram implements CommandLineRunner {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void main(String[] args) {
        SpringApplication.run(ClientProgram.class, args);
    }

    @Override
    public void run(String... args) throws IOException, InterruptedException {
        JcaKeyGenerateResponse key = generateKey();
//        x509(args);
//        mtls(args);
//        sshCa(args);
        System.exit(0);
    }

    public void sshCa(String... args) throws Exception {
        try (HttpClient client = HttpClient.newHttpClient()) {
            Map<String, Object> sshCaKey = null;
            {
                Map<String, Object> request = new HashMap<>();
                request.put("size", "2048");
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-issuer-api.khmer.name/api/ssh/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                sshCaKey = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }

            Map<String, Object> sshClient = null;
            {
                Map<String, Object> issuer = new HashMap<>();
                issuer.put("keyId", sshCaKey.get("keyId"));
                issuer.put("keyPassword", sshCaKey.get("keyPassword"));
                Map<String, Object> request = new HashMap<>();
                request.put("issuer", issuer);
                request.put("opensshPublicKey", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQClwFPqhyptjv9av32YK09AqXDCIgcYzIrapN8sBtvZxZvjSo3rp5LkBC5Cerhh23VKHr2gwFUvW/szKQEcS5Zgu0I4vrVwMcKGFbDz/CAgdBsoiscjO/d7vLK01MS/TvsU1uKMKArZPArqwQpYoT7TLZTKVd7RwPm/udSi/jNTSzIL1+/xDUtZpcuu9sIxS2jPBEZvvSgaJcnc1uDlL03HPrRNqx5O/CXGDCyUH+ATea9IQGqbflUB3DDXFSDM8oOOMNXGMOhre8HM5B7pCOekH93U+Gbzw9HHsZfxFsmqT19uvtZe9LeqelbabYMMZvTAJjBsNaS4+Z4IPa/hs7PBIuASKjtFI73sA28wa32MDz8iDAygL97vW9wLo1zPbyELh9CEF/haAd4JPm04Zx3pq7osfaiWQ8tc1APH9cqNY+lbnMKnWGN8HLMaia+/RYKT03alAnW7HMvCk1f7oXBkqdeAbDZ2nLy5zvaKgw9UgOa7a6VTSUKwgJg6nDdod18= dev");
                request.put("principal", "socheat");
                request.put("server", "192.168.1.1");
                request.put("validityPeriod", 1000);

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-issuer-api.khmer.name/api/ssh/client/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                sshClient = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }
//            FileUtils.write(new File("pki-mtls-server.pem"), (String) mtlsServer.get("certificate"));
//            FileUtils.write(new File("pki-mtls-client-cert.pem"), (String) mtlsClient.get("cert"));
//            FileUtils.write(new File("pki-mtls-client-privkey.pem"), (String) mtlsClient.get("privkey"));
            System.out.println("openssl verify -CAfile pki-mtls-server.pem pki-mtls-client-cert.pem");
        }
    }

    public void mtls(String... args) throws Exception {
        try (HttpClient client = HttpClient.newHttpClient()) {
            Map<String, Object> mtlsServerKey = null;
            {
                Map<String, Object> request = new HashMap<>();
                request.put("size", "2048");
                request.put("format", "RSA");
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-key-api.khmer.name/api/jca/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                mtlsServerKey = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }
            Map<String, Object> mtlsServer = null;
            {
                Map<String, Object> request = new HashMap<>();
                request.put("keyId", mtlsServerKey.get("keyId"));
                request.put("keyPassword", mtlsServerKey.get("keyPassword"));
                request.put("locality", "Phnom Penh");
                request.put("province", "Kandal");
                request.put("country", "KH");
                request.put("commonName", "mTLS Server");
                request.put("organization", "Ministry of Post and Telecommunications");
                request.put("organizationalUnit", "Digital Government Committee");

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-issuer-api.khmer.name/api/mtls/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                mtlsServer = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }

            Map<String, Object> mtlsClientKey = null;
            {
                Map<String, Object> request = new HashMap<>();
                request.put("size", "2048");
                request.put("format", "RSA");
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-key-api.khmer.name/api/jca/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                mtlsClientKey = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }
            Map<String, Object> mtlsClient = null;
            {
                Map<String, Object> issuer = new HashMap<>();
                issuer.put("certificateId", mtlsServer.get("certificateId"));
                issuer.put("keyPassword", mtlsServer.get("keyPassword"));
                Map<String, Object> request = new HashMap<>();
                request.put("issuer", issuer);
                request.put("keyId", mtlsClientKey.get("keyId"));
                request.put("keyPassword", mtlsClientKey.get("keyPassword"));
                request.put("locality", "Phnom Penh");
                request.put("province", "Kandal");
                request.put("country", "KH");
                request.put("commonName", "mTLS Client");
                request.put("organization", "Ministry of Post and Telecommunications");
                request.put("organizationalUnit", "Digital Government Committee");

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-issuer-api.khmer.name/api/mtls/client/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                mtlsClient = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }
            FileUtils.write(new File("pki-mtls-server.pem"), (String) mtlsServer.get("certificate"));
            FileUtils.write(new File("pki-mtls-client-cert.pem"), (String) mtlsClient.get("cert"));
            FileUtils.write(new File("pki-mtls-client-privkey.pem"), (String) mtlsClient.get("privkey"));
            System.out.println("openssl verify -CAfile pki-mtls-server.pem pki-mtls-client-cert.pem");
        }
    }

    public void x509(String... args) throws Exception {
        try (HttpClient client = HttpClient.newHttpClient()) {
            Map<String, Object> rootCaKey = null;
            {
                Map<String, Object> request = new HashMap<>();
                request.put("size", "2048");
                request.put("format", "RSA");
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-api-key.khmer.name/api/jca/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                rootCaKey = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }
            Map<String, Object> rootCa = null;
            {
                Map<String, Object> request = new HashMap<>();
                request.put("keyId", rootCaKey.get("keyId"));
                request.put("keyPassword", rootCaKey.get("keyPassword"));
                request.put("locality", "Phnom Penh");
                request.put("province", "Kandal");
                request.put("country", "KH");
                request.put("commonName", "Cambodia National CA");
                request.put("organization", "Ministry of Post and Telecommunications");
                request.put("organizationalUnit", "Digital Government Committee");

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-api-root.khmer.name/api/root/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                rootCa = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }
            Map<String, Object> subCaKey = null;
            {
                Map<String, Object> request = new HashMap<>();
                request.put("size", "2048");
                request.put("format", "RSA");
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-api-key.khmer.name/api/jca/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                subCaKey = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }
            Map<String, Object> subCa = null;
            {
                Map<String, Object> issuer = new HashMap<>();
                issuer.put("certificateId", rootCa.get("certificateId"));
                issuer.put("keyPassword", rootCa.get("keyPassword"));
                Map<String, Object> request = new HashMap<>();
                request.put("issuer", issuer);
                request.put("keyId", subCaKey.get("keyId"));
                request.put("keyPassword", subCaKey.get("keyPassword"));
                request.put("locality", "Phnom Penh");
                request.put("province", "Kandal");
                request.put("country", "KH");
                request.put("commonName", "Cambodia National RootCA");
                request.put("organization", "Ministry of Post and Telecommunications");
                request.put("organizationalUnit", "Digital Government Committee");

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-api-root.khmer.name/api/intermediate/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                subCa = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }
            {
                Map<String, Object> issuer = new HashMap<>();
                issuer.put("certificateId", rootCa.get("certificateId"));
                issuer.put("keyPassword", rootCa.get("keyPassword"));
                Map<String, Object> request = new HashMap<>();
                request.put("issuer", issuer);
                request.put("keyId", subCaKey.get("keyId"));
                request.put("keyPassword", subCaKey.get("keyPassword"));
                request.put("locality", "Phnom Penh");
                request.put("province", "Kandal");
                request.put("country", "KH");
                request.put("commonName", "Cambodia National Intermediate CA");
                request.put("organization", "Ministry of Post and Telecommunications");
                request.put("organizationalUnit", "Digital Government Committee");

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-api-issuer.khmer.name/api/intermediate/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                subCa = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }
            Map<String, Object> leafKey = null;
            {
                Map<String, Object> request = new HashMap<>();
                request.put("size", "2048");
                request.put("format", "RSA");
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-api-key.khmer.name/api/jca/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                leafKey = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }
            Map<String, Object> leaf = null;
            {
                Map<String, Object> issuer = new HashMap<>();
                issuer.put("certificateId", subCa.get("certificateId"));
                issuer.put("keyPassword", subCa.get("keyPassword"));
                Map<String, Object> request = new HashMap<>();
                request.put("issuer", issuer);
                request.put("keyId", leafKey.get("keyId"));
                request.put("keyPassword", leafKey.get("keyPassword"));
                request.put("locality", "Phnom Penh");
                request.put("province", "Kandal");
                request.put("country", "KH");
                request.put("commonName", "127.0.0.1");
                request.put("organization", "Ministry of Post and Telecommunications");
                request.put("organizationalUnit", "Digital Government Committee");
                request.put("sans", List.of("127.0.0.1", "localhost"));

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-issuer-api.khmer.name/api/server/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                leaf = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }
            {
                Map<String, Object> request = new HashMap<>();
                request.put("keyId", rootCaKey.get("keyId"));
                request.put("keyPassword", rootCaKey.get("keyPassword"));
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-api-revoke.khmer.name/api/revoke/key"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                System.out.println(resp.statusCode());
            }
            FileUtils.write(new File("/opt/apps/tls/root-ca.pem"), (String) rootCa.get("certificate"));
            FileUtils.write(new File("/opt/apps/tls/127.0.0.1/fullchain.pem"), (String) leaf.get("fullchain"));
            FileUtils.write(new File("/opt/apps/tls/127.0.0.1/privkey.pem"), (String) leaf.get("privkey"));
            System.out.println("openssl verify -CAfile /opt/apps/tls/root-ca.pem /opt/apps/tls/127.0.0.1/fullchain.pem");
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

}
