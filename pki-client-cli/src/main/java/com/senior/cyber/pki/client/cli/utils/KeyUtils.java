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

public class KeyUtils {

    private static final String KEY = "https://pki-api-key.khmer.name";
//        private static final String KEY = "http://127.0.0.1:3103";

    private static final ObjectMapper MAPPER = new ObjectMapper();

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

}
