package com.senior.cyber.pki.client.cli.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.*;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.desktop.YubiKitManager;
import com.yubico.yubikit.management.DeviceInfo;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Map;

public class ClientUtils {

    private static final String ISSUER = "https://pki-api-issuer.khmer.name";
//        private static final String ISSUER = "http://127.0.0.1:3101";

    private static final String KEY = "https://pki-api-key.khmer.name";
//        private static final String KEY = "http://127.0.0.1:3103";

    private static final String QUEUE = "https://pki-api-queue.khmer.name";
//        private static final String QUEUE = "http://127.0.0.1:3105";

    private static final String REVOKE = "https://pki-api-revoke.khmer.name";
//        private static final String REVOKE = "http://127.0.0.1:3005";

    private static final String ROOT = "https://pki-api-root.khmer.name";
//    private static final String ROOT = "http://127.0.0.1:3102";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static ServerInfoResponse serverInfoV1() throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(ROOT + "/api/server/info"))
                    .GET()
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), ServerInfoResponse.class);
        }
    }

    public static RootGenerateResponse rootGenerate(RootGenerateRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
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

    public static RootRegisterResponse rootRegister(RootRegisterRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(ROOT + "/api/root/register"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), RootRegisterResponse.class);
        }
    }

    public static SubordinateRegisterResponse subordinateRegister(SubordinateRegisterRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(ROOT + "/api/subordinate/register"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), SubordinateRegisterResponse.class);
        }
    }

    public static SubordinateGenerateResponse subordinateGenerate(SubordinateGenerateRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
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

    public static IssuerGenerateResponse issuerGenerateV1(IssuerGenerateRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
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

    public static RevokeCertificateResponse revokeCertificate(RevokeCertificateRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(REVOKE + "/api/revoke/certificate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), RevokeCertificateResponse.class);
        }
    }

    public static RevokeKeyResponse revokeKey(RevokeKeyRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(REVOKE + "/api/revoke/key"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), RevokeKeyResponse.class);
        }
    }

    public static KeyInfoResponse info(KeyInfoRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(KEY + "/api/info"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), KeyInfoResponse.class);
        }
    }

    public static KeyDownloadResponse download(KeyDownloadRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(KEY + "/api/download"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), KeyDownloadResponse.class);
        }
    }

    public static YubicoInfoResponse yubicoInfo() throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(KEY + "/api/yubico/info"))
                    .GET()
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            YubicoInfoResponse response = MAPPER.readValue(resp.body(), YubicoInfoResponse.class);
            if (response.getItems() == null) {
                response.setItems(new ArrayList<>());
            }

            YubiKitManager manager = new YubiKitManager();
            for (Map.Entry<YubiKeyDevice, DeviceInfo> p : manager.listAllDevices().entrySet()) {
                YubicoInfo _info = YubicoInfo.builder().build();
                response.getItems().add(_info);
                YubiKeyDevice device = p.getKey();
                DeviceInfo info = p.getValue();
                _info.setTransport(device.getTransport().name());
                _info.setVersion(String.valueOf(info.getVersion()));
                if (info.getSerialNumber() != null) {
                    _info.setSerialNumber(String.valueOf(info.getSerialNumber()));
                }
                if (info.getPartNumber() != null && !"null".equals(info.getPartNumber())) {
                    _info.setPartNumber(String.valueOf(info.getPartNumber()));
                }
                _info.setFormFactor(info.getFormFactor().name());
                _info.setVersionName(info.getVersionName());
                _info.setType("client");
            }
            return response;
        }
    }

    public static KeyGenerateResponse bcServerGenerate(BcGenerateRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(KEY + "/api/bc/generate"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), KeyGenerateResponse.class);
        }
    }

    public static KeyGenerateResponse bcClientRegister(BcRegisterRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(KEY + "/api/bc/register"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), KeyGenerateResponse.class);
        }
    }

    public static KeyGenerateResponse yubicoRegister(YubicoRegisterRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
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

    public static KeyGenerateResponse yubicoGenerate(YubicoGenerateRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
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

    public static ServerInfoResponse serverInfoV2() throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(ISSUER + "/api/server/info"))
                    .GET()
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), ServerInfoResponse.class);
        }
    }

    public static SshClientGenerateResponse sshClientGenerate(SshClientGenerateRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
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

    public static IssuerGenerateResponse issuerGenerateV2(IssuerGenerateRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
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

    public static MtlsGenerateResponse mtlsGenerate(MtlsGenerateRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
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

    public static MtlsClientGenerateResponse mtlsClientGenerate(MtlsClientGenerateRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
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

    public static ServerGenerateResponse serverGenerate(ServerGenerateRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
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

    public static QueueRequestResponse queueRequest(QueueRequestRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(QUEUE + "/api/queue/request"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), QueueRequestResponse.class);
        }
    }

    public static QueueSearchResponse queueSearch(QueueSearchRequest request) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(QUEUE + "/api/queue/search"))
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), QueueSearchResponse.class);
        }
    }

    public static QueueResponse queue(String id) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(QUEUE + "/api/queue/" + id))
                    .GET()
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return MAPPER.readValue(resp.body(), QueueResponse.class);
        }
    }

}
