package com.senior.cyber.pki.service;

import com.senior.cyber.pki.common.util.YubicoProviderUtils;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.fido.client.BasicWebAuthnClient;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.*;
import com.yubico.yubikit.oath.ParseUriException;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

public class Program1 {

    public static void main(String[] args) throws IOException, CommandException, NoSuchAlgorithmException, ParseUriException, URISyntaxException, ClientError {
        YubiKeyDevice device = YubicoProviderUtils.lookupDevice("23275988");
        fido2(device);

    }

    public static void fido2(YubiKeyDevice device) throws IOException, URISyntaxException, ClientError, CommandException {
        if (!device.supportsConnection(FidoConnection.class)) {
            System.err.println("❌ This YubiKey does not support FIDO2.");
            return;
        }

        try (FidoConnection connection = device.openConnection(FidoConnection.class)) {
            Ctap2Session ctapSession = new Ctap2Session(connection);
            BasicWebAuthnClient client = new BasicWebAuthnClient(ctapSession);

            // Domain must be DNS-valid for YubiKey (nip.io resolves to 127.0.0.1)
            String rpDomain = "abc123.ngrok.io"; // use your actual ngrok HTTPS domain
            String origin = "https://" + rpDomain;

            // Step 1: Random challenge
            byte[] challenge = new byte[32];
            new SecureRandom().nextBytes(challenge);

            // Step 2: Create clientDataJSON manually
            String encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);
            String clientDataJsonString = "{"
                    + "\"type\":\"webauthn.create\","
                    + "\"challenge\":\"" + encodedChallenge + "\","
                    + "\"origin\":\"" + origin + "\""
                    + "}";
            byte[] clientDataJson = clientDataJsonString.getBytes(StandardCharsets.UTF_8);

            // Step 3: Relying party
            PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity(rpDomain, "abc123.ngrok.io");

            // Step 4: User entity
            PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(
                    "user@example.com",
                    UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                    "Test User"
            );

            // Step 5: Credential parameters
            PublicKeyCredentialParameters pubKeyParams = new PublicKeyCredentialParameters(
                    PublicKeyCredentialType.PUBLIC_KEY,
                    -7 // ES256
            );

            // Step 6: Authenticator selection
            AuthenticatorSelectionCriteria selection = new AuthenticatorSelectionCriteria(
                    AuthenticatorAttachment.CROSS_PLATFORM,
                    ResidentKeyRequirement.DISCOURAGED,
                    UserVerificationRequirement.PREFERRED
            );

            // Step 7: Create options
            PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
                    rp,
                    user,
                    challenge,
                    Collections.singletonList(pubKeyParams),
                    60000L,
                    null,
                    selection,
                    "none",
                    null
            );

            // Step 8: Call makeCredential
            PublicKeyCredential credential = client.makeCredential(
                    clientDataJson,
                    options,
                    rpDomain,
                    "123456".toCharArray(),   // PIN if set (char[]), or null
                    null,   // enterpriseAttestation
                    null    // commandState
            );

//            // Step 9: Output result


            System.out.println("✅ Credential Created:");
            System.out.println(" - id : " + credential.getId());
            System.out.println(" - type : " + credential.getType());
            System.out.println(" - rawId : " + Base64.getUrlEncoder().withoutPadding().encodeToString(credential.getRawId()));
            ClientExtensionResults clientExtensionResults = credential.getClientExtensionResults();
            if (clientExtensionResults != null) {
                Map<String, Object> o = clientExtensionResults.toMap(SerializationType.JSON);
                if (!o.isEmpty()) {
                    System.out.println(" - clientExtensionResults");
                    for (Map.Entry<String, Object> i : o.entrySet()) {
                        if (i.getValue() != null) {
                            System.out.println("    - " + i.getKey() + " : " + i.getValue());
                        }
                    }
                }
            }
            AuthenticatorAttestationResponse response = (AuthenticatorAttestationResponse) credential.getResponse();
            System.out.println(" - response");
            System.out.println("   - clientDataJson : " + new String(response.getClientDataJson(), StandardCharsets.UTF_8));
            System.out.println("   - transports : " + StringUtils.join(response.getTransports(), ", "));
            System.out.println("   - PublicKeyAlgorithm : " + response.getPublicKeyAlgorithm());
            System.out.println("   - PublicKey : " + Base64.getEncoder().encodeToString(response.getPublicKey()));
            System.out.println("   - AttestationObject : " + Base64.getEncoder().encodeToString(response.getAttestationObject()));
            AuthenticatorData authenticatorData = response.getAuthenticatorData();
            System.out.println("   - authenticatorData");
            System.out.println("     - Bytes : " + Base64.getEncoder().encodeToString(authenticatorData.getBytes()));
            System.out.println(" - RpIdHash : " + Base64.getEncoder().encodeToString(authenticatorData.getRpIdHash()));
            System.out.println(" - SignCount : " + authenticatorData.getSignCount());
            System.out.println(" - Flags : " + authenticatorData.getFlags());
            if (authenticatorData.getExtensions() != null) {
                for (Map.Entry<String, ?> extension : authenticatorData.getExtensions().entrySet()) {
                    System.out.println(extension.getKey());
                }
            }
            AttestedCredentialData data = authenticatorData.getAttestedCredentialData();
            System.out.println(" - Aaguid : " + Base64.getEncoder().encodeToString(data.getAaguid()));
            System.out.println(" - CredentialId : " + Base64.getEncoder().encodeToString(data.getCredentialId()));
            if (data.getCosePublicKey() != null) {
                for (Map.Entry<Integer, ?> entry : data.getCosePublicKey().entrySet()) {
                    System.out.println(entry.getKey());
                    Object p = entry.getValue();
                    if (p instanceof Integer) {
                        System.out.println(p);
                    } else if (p instanceof byte[] v) {
                        System.out.println(Base64.getEncoder().encodeToString(v));
                    }
                }
            }

//            System.out.println(" - Format: " + attestation.getFormat());
//            System.out.println(" - PublicKey: " + Base64.getEncoder().encodeToString(attestation.getCredentialPublicKey()));
        }
    }

}
