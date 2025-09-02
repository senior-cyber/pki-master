package com.senior.cyber.pki.service;

import com.senior.cyber.pki.service.util.YubicoProviderUtils;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.otp.Modhex;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.fido.client.BasicWebAuthnClient;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.*;
import com.yubico.yubikit.oath.CredentialData;
import com.yubico.yubikit.oath.OathSession;
import com.yubico.yubikit.oath.ParseUriException;
import com.yubico.yubikit.yubiotp.*;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

public class Program {

    public static void main(String[] args) throws IOException, CommandException, NoSuchAlgorithmException, ParseUriException, URISyntaxException, ClientError {

//        YubiKitManager manager = new YubiKitManager();
//        for (Map.Entry<YubiKeyDevice, DeviceInfo> p : manager.listAllDevices().entrySet()) {
//            YubiKeyDevice device = p.getKey();
//            DeviceInfo info = p.getValue();
//            System.out.println(info.getSerialNumber());
//        }

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
            String rpDomain = "127.0.0.1.nip.io";
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
            PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity(rpDomain, "Test RP");

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
                    null,   // PIN if set (char[]), or null
                    null,   // enterpriseAttestation
                    null    // commandState
            );

//            // Step 9: Output result
//            System.out.println("✅ Credential Created:");
//            System.out.println(" - ID: " + Base64.getUrlEncoder().withoutPadding().encodeToString(credential.getId()));
//            System.out.println(" - Format: " + credential.getResponse().getFormat());
//            System.out.println(" - PublicKey: " + Base64.getEncoder().encodeToString(credential.getResponse().getCredentialPublicKey()));
        }
    }

    public static void oathTotp(YubiKeyDevice device) throws IOException, CommandException, URISyntaxException, ParseUriException {
        if (device.supportsConnection(SmartCardConnection.class)) {
            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                // Initialize OATH application
                OathSession session = new OathSession(connection);

                URI uri = new URI("otpauth://totp/Example:demo@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example");

                CredentialData data = CredentialData.parseUri(uri); // parse from URI :contentReference[oaicite:5]{index=5}
                System.out.println("Parsed credential:");
                System.out.println("  Account: " + data.getAccountName());
                System.out.println("  Issuer:  " + data.getIssuer());
                System.out.println("  Period:  " + data.getPeriod());
                System.out.println("  Digits:  " + data.getDigits());

                // Write to key
                session.putCredential(data, false);
                System.out.println("TOTP credential written successfully.");
            }
        }
    }

    public static void oathHotp(YubiKeyDevice device) throws IOException, CommandException, NoSuchAlgorithmException, URISyntaxException, ParseUriException {
        if (device.supportsConnection(SmartCardConnection.class)) {
            try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
                // Initialize OATH application
                OathSession session = new OathSession(connection);

                URI uri = new URI("otpauth://hotp/Test:hotp@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test&counter=0");

                CredentialData data = CredentialData.parseUri(uri); // parse from URI :contentReference[oaicite:5]{index=5}
                System.out.println("Parsed credential:");
                System.out.println("  Account: " + data.getAccountName());
                System.out.println("  Issuer:  " + data.getIssuer());
                System.out.println("  Period:  " + data.getPeriod());
                System.out.println("  Digits:  " + data.getDigits());

                // Write to key
                session.putCredential(data, false);
                System.out.println("TOTP credential written successfully.");
            }
        }
    }

    /**
     * yubico OTP
     *
     * @param device
     * @throws IOException
     * @throws CommandException
     * @throws NoSuchAlgorithmException
     */
    public static void yubicoOtp(YubiKeyDevice device) throws IOException, CommandException, NoSuchAlgorithmException {
        if (device.supportsConnection(OtpConnection.class)) {
            try (OtpConnection connection = device.openConnection(OtpConnection.class)) {
                YubiOtpSession session = new YubiOtpSession(connection);

                // 1) Serial → public ID (modhex), like --serial-public-id
                int serial = session.getSerialNumber(); // may throw if serial isn't API-visible. :contentReference[oaicite:3]{index=3}
                // ykman’s --serial-public-id uses the device serial as the public ID in modhex.
                // We encode the serial as 6 bytes big-endian and modhex-encode → 12 chars.
                byte[] serial6 = new byte[6];
                for (int i = 5; i >= 0; i--) {
                    serial6[i] = (byte) (serial & 0xFF);
                    serial >>>= 8;
                }
                String publicIdModhex = Modhex.encode(serial6); // com.yubico.yubikit.core.otp.Modhex :contentReference[oaicite:4]{index=4}


                // 2) Generate private ID (6 bytes) and secret key (16 bytes), like -g and -G
                SecureRandom rng = SecureRandom.getInstanceStrong();
                byte[] privateId = new byte[6];
                byte[] secretKey = new byte[16];
                rng.nextBytes(privateId);
                rng.nextBytes(secretKey);

                String privateIdHex = HexFormat.of().formatHex(privateId);
                String secretKeyHex = HexFormat.of().formatHex(secretKey);

                System.out.println("Using YubiKey serial as public ID: " + publicIdModhex);
                System.out.println("Using a randomly generated private ID: " + privateIdHex);
                System.out.println("Using a randomly generated secret key: " + secretKeyHex);

                // 4) Build and write configuration to SLOT 1
                // publicId (modhex) -> bytes; privateId/key are raw bytes.
                byte[] publicIdBytes = Modhex.decode(publicIdModhex);

                YubiOtpSlotConfiguration configuration = new YubiOtpSlotConfiguration(publicIdBytes, privateId, secretKey);
                // With default flags this mimics "ykman otp yubiotp 1 ..." behavior. :contentReference[oaicite:5]{index=5}

                session.putConfiguration(Slot.ONE, configuration, null, null); // write, no access code. :contentReference[oaicite:6]{index=6}
                System.out.println("Slot 1 programmed.");
            }
        }
    }

    /**
     * yubico OTP
     *
     * @param device
     * @throws IOException
     * @throws CommandException
     * @throws NoSuchAlgorithmException
     */
    public static void yubicoOtpChallengeResponse(YubiKeyDevice device) throws IOException, CommandException, NoSuchAlgorithmException {
        if (device.supportsConnection(OtpConnection.class)) {
            try (OtpConnection connection = device.openConnection(OtpConnection.class)) {
                YubiOtpSession session = new YubiOtpSession(connection);
                // Generate a random 20-byte key (max allowed)
                byte[] secretKey = new byte[20];
                SecureRandom.getInstanceStrong().nextBytes(secretKey);

                String hexKey = HexFormat.of().formatHex(secretKey);
                System.out.println("Generated HMAC-SHA1 Key: " + hexKey);

                // Create config (with user-visible option like require touch)
                HmacSha1SlotConfiguration configuration = new HmacSha1SlotConfiguration(secretKey);
                configuration.requireTouch(false);

                session.putConfiguration(Slot.ONE, configuration, null, null); // write, no access code. :contentReference[oaicite:6]{index=6}
                System.out.println("Slot 1 programmed.");
            }
        }
    }

    public static void yubicoHotp(YubiKeyDevice device) throws IOException, CommandException, NoSuchAlgorithmException {
        if (device.supportsConnection(OtpConnection.class)) {
            try (OtpConnection connection = device.openConnection(OtpConnection.class)) {
                YubiOtpSession session = new YubiOtpSession(connection);
                // 1. Generate a random 20-byte HOTP secret (maximum allowed)
                byte[] secretKey = new byte[20];
                SecureRandom.getInstanceStrong().nextBytes(secretKey);

                // Optional: encode as hex for printing
                System.out.println("Generated HOTP Key: " + HexFormat.of().formatHex(secretKey));

                // 2. Create HOTP slot configuration
                HotpSlotConfiguration configuration = new HotpSlotConfiguration(secretKey);

                // 3. Program to slot (e.g., SLOT.ONE or SLOT.TWO)
                session.putConfiguration(Slot.ONE, configuration, null, null);
                System.out.println("HOTP configuration written to Slot 1.");
            }
        }
    }

    public static void yubicoStaticPassword(YubiKeyDevice device) throws IOException, CommandException, NoSuchAlgorithmException {
        if (device.supportsConnection(OtpConnection.class)) {
            try (OtpConnection connection = device.openConnection(OtpConnection.class)) {
                YubiOtpSession session = new YubiOtpSession(connection);

                String password = "<!3z#b1K]hB0QtipsuC!U&oU7lN^+SVHwFU7o>";
                byte[] scanCodes = toScanCodeBytes(password);
                StaticPasswordSlotConfiguration configuration = new StaticPasswordSlotConfiguration(scanCodes);

                // 3. Program to slot (e.g., SLOT.ONE or SLOT.TWO)
                session.putConfiguration(Slot.ONE, configuration, null, null);
                System.out.println("HOTP configuration written to Slot 1.");
            }
        }
    }

    public static void yubicoStaticTicket(YubiKeyDevice device) throws IOException, CommandException, NoSuchAlgorithmException {
        if (device.supportsConnection(OtpConnection.class)) {
            try (OtpConnection connection = device.openConnection(OtpConnection.class)) {
                YubiOtpSession session = new YubiOtpSession(connection);

                // Step 1: Generate values (16 bytes = 32 modhex chars)
                SecureRandom random = SecureRandom.getInstanceStrong();

                byte[] fixed = new byte[6]; // Public ID = 12 modhex characters
                byte[] uid = new byte[6];   // Private ID
                byte[] key = new byte[16];  // AES key

                random.nextBytes(fixed);
                random.nextBytes(uid);
                random.nextBytes(key);

                // Step 2: Create OTP configuration
                StaticTicketSlotConfiguration configuration = new StaticTicketSlotConfiguration(fixed, uid, key);


                // 3. Program to slot (e.g., SLOT.ONE or SLOT.TWO)
                session.putConfiguration(Slot.ONE, configuration, null, null);
                System.out.println("HOTP configuration written to Slot 1.");
            }
        }
    }

    // Struct to hold scan code and whether Shift is required
    public static class ScanCode {
        public final byte code;
        public final boolean requiresShift;

        public ScanCode(int code, boolean shift) {
            this.code = (byte) code;
            this.requiresShift = shift;
        }
    }

    private static final Map<Character, ScanCode> US_QWERTY_MAP = new HashMap<>();

    static {
        // Digits
        US_QWERTY_MAP.put('1', new ScanCode(0x1E, false));
        US_QWERTY_MAP.put('!', new ScanCode(0x1E, true));
        US_QWERTY_MAP.put('2', new ScanCode(0x1F, false));
        US_QWERTY_MAP.put('@', new ScanCode(0x1F, true));
        US_QWERTY_MAP.put('3', new ScanCode(0x20, false));
        US_QWERTY_MAP.put('#', new ScanCode(0x20, true));
        US_QWERTY_MAP.put('4', new ScanCode(0x21, false));
        US_QWERTY_MAP.put('$', new ScanCode(0x21, true));
        US_QWERTY_MAP.put('5', new ScanCode(0x22, false));
        US_QWERTY_MAP.put('%', new ScanCode(0x22, true));
        US_QWERTY_MAP.put('6', new ScanCode(0x23, false));
        US_QWERTY_MAP.put('^', new ScanCode(0x23, true));
        US_QWERTY_MAP.put('7', new ScanCode(0x24, false));
        US_QWERTY_MAP.put('&', new ScanCode(0x24, true));
        US_QWERTY_MAP.put('8', new ScanCode(0x25, false));
        US_QWERTY_MAP.put('*', new ScanCode(0x25, true));
        US_QWERTY_MAP.put('9', new ScanCode(0x26, false));
        US_QWERTY_MAP.put('(', new ScanCode(0x26, true));
        US_QWERTY_MAP.put('0', new ScanCode(0x27, false));
        US_QWERTY_MAP.put(')', new ScanCode(0x27, true));

        // Letters
        for (char c = 'a'; c <= 'z'; c++) {
            US_QWERTY_MAP.put(c, new ScanCode(0x04 + (c - 'a'), false));
        }
        for (char c = 'A'; c <= 'Z'; c++) {
            US_QWERTY_MAP.put(c, new ScanCode(0x04 + (c - 'A'), true));
        }

        // Common symbols
        US_QWERTY_MAP.put('-', new ScanCode(0x2D, false));
        US_QWERTY_MAP.put('_', new ScanCode(0x2D, true));
        US_QWERTY_MAP.put('=', new ScanCode(0x2E, false));
        US_QWERTY_MAP.put('+', new ScanCode(0x2E, true));
        US_QWERTY_MAP.put('[', new ScanCode(0x2F, false));
        US_QWERTY_MAP.put('{', new ScanCode(0x2F, true));
        US_QWERTY_MAP.put(']', new ScanCode(0x30, false));
        US_QWERTY_MAP.put('}', new ScanCode(0x30, true));
        US_QWERTY_MAP.put('\\', new ScanCode(0x31, false));
        US_QWERTY_MAP.put('|', new ScanCode(0x31, true));
        US_QWERTY_MAP.put(';', new ScanCode(0x33, false));
        US_QWERTY_MAP.put(':', new ScanCode(0x33, true));
        US_QWERTY_MAP.put('\'', new ScanCode(0x34, false));
        US_QWERTY_MAP.put('"', new ScanCode(0x34, true));
        US_QWERTY_MAP.put(',', new ScanCode(0x36, false));
        US_QWERTY_MAP.put('<', new ScanCode(0x36, true));
        US_QWERTY_MAP.put('.', new ScanCode(0x37, false));
        US_QWERTY_MAP.put('>', new ScanCode(0x37, true));
        US_QWERTY_MAP.put('/', new ScanCode(0x38, false));
        US_QWERTY_MAP.put('?', new ScanCode(0x38, true));
        US_QWERTY_MAP.put(' ', new ScanCode(0x2C, false));
    }

    public static byte[] toScanCodeBytes(String input) {
        List<Byte> result = new ArrayList<>();

        for (char c : input.toCharArray()) {
            ScanCode code = US_QWERTY_MAP.get(c);
            if (code == null) {
                throw new IllegalArgumentException("Unsupported character: " + c);
            }

            byte encoded;
            if (code.requiresShift) {
                encoded = (byte) (code.code | 0x80); // Use high bit to indicate SHIFT
            } else {
                encoded = code.code;
            }

            result.add(encoded);
        }

        if (result.size() > 38) {
            throw new IllegalArgumentException("Password too long (max 38 scan codes)");
        }

        byte[] output = new byte[result.size()];
        for (int i = 0; i < output.length; i++) {
            output[i] = result.get(i);
        }
        return output;
    }

}
