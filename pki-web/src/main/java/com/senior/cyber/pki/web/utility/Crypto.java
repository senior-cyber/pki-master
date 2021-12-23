package com.senior.cyber.pki.web.utility;

import com.senior.cyber.frmk.common.crypto.AESGCMBlockCipher;
import com.senior.cyber.frmk.common.crypto.IESCipherGCM;
import com.senior.cyber.frmk.common.crypto.IESEngineGCM;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

public class Crypto {

    private final int keySize;

    private final int tagLength;

    private final SecureRandom secureRandom;

    public Crypto() {
        this.secureRandom = new SecureRandom();
        this.tagLength = 12;
        this.keySize = 256;
    }

    public String decrypt(PrivateKey privateKey, String text) throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        IESCipherGCM cipher = new IESCipherGCM(new IESEngineGCM(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()), new AESGCMBlockCipher()), this.tagLength);
        cipher.engineInit(Cipher.DECRYPT_MODE, privateKey, new IESParameterSpec(null, null, 128, 128, null), this.secureRandom);
        byte[] data = Base64.getDecoder().decode(text);
        return new String(cipher.engineDoFinal(data, 0, data.length), StandardCharsets.UTF_8);
    }

    public String decrypt(SecretKey secretKey, String text) throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        int dotIndex = text.indexOf('.');
        String iv = text.substring(0, dotIndex);
        String cipherText = text.substring(dotIndex + 1);
        GCMParameterSpec gcm = new GCMParameterSpec(this.tagLength * 8, Base64.getDecoder().decode(iv));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcm);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)), StandardCharsets.UTF_8);
    }

    public String encrypt(SecretKey secretKey, String text) throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        byte[] iv = this.secureRandom.generateSeed(this.tagLength);
        GCMParameterSpec gcm = new GCMParameterSpec(this.tagLength * 8, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcm);
        return Base64.getEncoder().encodeToString(iv) + "." + Base64.getEncoder().encodeToString(cipher.doFinal(text.getBytes(StandardCharsets.UTF_8)));
    }

    public String encrypt(PublicKey publicKey, String text) throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        IESCipherGCM cipher = new IESCipherGCM(new IESEngineGCM(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()), new AESGCMBlockCipher()), this.tagLength);
        cipher.engineInit(Cipher.ENCRYPT_MODE, publicKey, new IESParameterSpec(null, null, 128, 128, null), this.secureRandom);
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        return Base64.getEncoder().encodeToString(cipher.engineDoFinal(data, 0, data.length));
    }

    public SecretKey lookupKeyAgreement(ECPrivateKey yours, ECPublicKey others) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
        agreement.init(yours);
        agreement.doPhase(others, true);
        byte[] secretData = agreement.generateSecret();
        int keyLength = secretData.length * 8;
        if (keyLength == this.keySize) {
            return new SecretKeySpec(secretData, 0, secretData.length, "AES");
        } else {
            throw new IllegalArgumentException("not support key size " + keyLength);
        }
    }

}