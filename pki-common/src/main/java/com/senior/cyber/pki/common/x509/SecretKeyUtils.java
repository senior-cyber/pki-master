package com.senior.cyber.pki.common.x509;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;

public class SecretKeyUtils {

    private static final SecureRandom RANDOM = new SecureRandom();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static SecretKey extractSecretKey(ECPrivateKey privateKey, ECPublicKey publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        byte[] secretData = keyAgreement.generateSecret();
        int keyLength = secretData.length * 8;
        if (keyLength == 256) {
            return new SecretKeySpec(secretData, 0, secretData.length, "AES");
        } else {
            throw new IllegalArgumentException("not support key size " + keyLength);
        }
    }

    public static String hashText(String text) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(digest.digest(text.getBytes(StandardCharsets.UTF_8)));
    }

    public static String hashText(String text, SecretKey secretKey) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        return Base64.getEncoder().encodeToString(mac.doFinal(text.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * AES_256/GCM/NoPadding
     *
     * @param secretKey
     * @param text
     * @return iv.cipher.tag
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static String encryptText(SecretKey secretKey, String text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        int length = 16;
        byte[] ivData = RANDOM.generateSeed(length);
        String ivText = Base64.getEncoder().encodeToString(ivData);

        Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding");
        GCMParameterSpec gcm = new GCMParameterSpec(ivData.length * 8, ivData);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcm);

        byte[] textData = text.getBytes(StandardCharsets.UTF_8);

        byte[] secretData = cipher.doFinal(textData);

        byte[] authenticationData = Arrays.copyOfRange(secretData, secretData.length - ivData.length, secretData.length);
        String authenticationText = Base64.getEncoder().encodeToString(authenticationData);
        byte[] cipherData = Arrays.copyOfRange(secretData, 0, secretData.length - ivData.length);
        String cipherText = Base64.getEncoder().encodeToString(cipherData);

        return ivText + "." + cipherText + "." + authenticationText;
    }

    /**
     * @param secretKey
     * @param text      iv.cipher.tag
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static String decryptText(SecretKey secretKey, String text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        int firstDotIndex = text.indexOf('.');
        int secondDotIndex = text.indexOf('.', firstDotIndex + 1);
        Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding");
        byte[] ivData = Base64.getDecoder().decode(text.substring(0, firstDotIndex));
        GCMParameterSpec gcm = new GCMParameterSpec(ivData.length * 8, ivData);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcm);
        byte[] cipherData = Base64.getDecoder().decode(text.substring(firstDotIndex + 1, secondDotIndex));
        byte[] authenticationData = Base64.getDecoder().decode(text.substring(secondDotIndex + 1));
        byte[] secretData = new byte[cipherData.length + authenticationData.length];
        System.arraycopy(cipherData, 0, secretData, 0, cipherData.length);
        System.arraycopy(authenticationData, 0, secretData, cipherData.length, authenticationData.length);
        byte[] textData = cipher.doFinal(secretData);
        return new String(textData, StandardCharsets.UTF_8);
    }

}
