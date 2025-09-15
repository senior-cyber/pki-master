package com.senior.cyber.pki.client.cli.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.*;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public class RevokeUtils {

    private static final String REVOKE = "https://pki-api-revoke.khmer.name";
//        private static final String REVOKE = "http://127.0.0.1:3005";

    private static final ObjectMapper MAPPER = new ObjectMapper();

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

}
