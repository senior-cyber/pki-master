package com.senior.cyber.pki.client.cli;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.FileUtils;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;
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

    public static void main(String[] args) throws Exception {
        SpringApplication.run(ClientProgram.class, args);
    }

    public void run2(String... args) throws Exception {
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
                Map<String, Object> request = new HashMap<>();
                request.put("issuerCertificateId", mtlsServer.get("issuerCertificateId"));
                request.put("issuerKeyPassword", mtlsServer.get("issuerKeyPassword"));
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
        System.exit(0);
    }

    public void run(String... args) throws Exception {
        try (HttpClient client = HttpClient.newHttpClient()) {
            Map<String, Object> rootCaKey = null;
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
                        .uri(URI.create("https://pki-root-api.khmer.name/api/root/generate"))
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
                        .uri(URI.create("https://pki-key-api.khmer.name/api/jca/generate"))
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
                Map<String, Object> request = new HashMap<>();
                request.put("issuerCertificateId", rootCa.get("issuerCertificateId"));
                request.put("issuerKeyPassword", rootCa.get("issuerKeyPassword"));
                request.put("keyId", subCaKey.get("keyId"));
                request.put("keyPassword", subCaKey.get("keyPassword"));
                request.put("locality", "Phnom Penh");
                request.put("province", "Kandal");
                request.put("country", "KH");
                request.put("commonName", "Cambodia National RootCA");
                request.put("organization", "Ministry of Post and Telecommunications");
                request.put("organizationalUnit", "Digital Government Committee");

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-root-api.khmer.name/api/intermediate/generate"))
                        .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                subCa = MAPPER.readValue(resp.body(), new TypeReference<>() {
                });
            }
            {
                Map<String, Object> request = new HashMap<>();
                request.put("issuerCertificateId", rootCa.get("issuerCertificateId"));
                request.put("issuerKeyPassword", rootCa.get("issuerKeyPassword"));
                request.put("keyId", subCaKey.get("keyId"));
                request.put("keyPassword", subCaKey.get("keyPassword"));
                request.put("locality", "Phnom Penh");
                request.put("province", "Kandal");
                request.put("country", "KH");
                request.put("commonName", "Cambodia National Intermediate CA");
                request.put("organization", "Ministry of Post and Telecommunications");
                request.put("organizationalUnit", "Digital Government Committee");

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://pki-issuer-api.khmer.name/api/intermediate/generate"))
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
                        .uri(URI.create("https://pki-key-api.khmer.name/api/jca/generate"))
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
                Map<String, Object> request = new HashMap<>();
                request.put("issuerCertificateId", subCa.get("issuerCertificateId"));
                request.put("issuerKeyPassword", subCa.get("issuerKeyPassword"));
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
            FileUtils.write(new File("/opt/apps/tls/root-ca.pem"), (String) rootCa.get("certificate"));
            FileUtils.write(new File("/opt/apps/tls/127.0.0.1/fullchain.pem"), (String) leaf.get("fullchain"));
            FileUtils.write(new File("/opt/apps/tls/127.0.0.1/privkey.pem"), (String) leaf.get("privkey"));
            // System.out.println("openssl verify -CAfile pki-root-ca.pem pki-sub-ca.pem pki-leaf.pem");

        }
        System.exit(0);
    }

}
