package com.senior.cyber.pki.common.x509;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;

public class PrivateKeyUtils {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static String signText(PrivateKey privateKey, String text) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = null;
        if (privateKey instanceof RSAPrivateKey) {
            signature = Signature.getInstance("SHA256withRSA");
        } else if (privateKey instanceof ECPrivateKey) {
            signature = Signature.getInstance("SHA256withECDSA");
        } else {
            throw new IllegalArgumentException(privateKey.getClass().getName() + " is not supported");
        }
        signature.initSign(privateKey, new SecureRandom());
        signature.update(text.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signature.sign()) + "." + text;
    }

    public static String decryptText(PrivateKey privateKey, String text) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        if (privateKey instanceof RSAPrivateKey) {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] textData = cipher.doFinal(Base64.getDecoder().decode(text));
            return new String(textData, StandardCharsets.UTF_8);
        } else if (privateKey instanceof ECPrivateKey) {
            int dotIndex = text.indexOf('.');
            byte[] iv = Base64.getDecoder().decode(text.substring(0, dotIndex));
            byte[] derivation = iv.clone();
            byte[] encoding = iv.clone();
            int length = iv.length;
            Cipher cipher = Cipher.getInstance("ECIESwithSHA256andAES-CBC", BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, new IESParameterSpec(derivation, encoding, length * 8, length * 8, iv, false));
            byte[] textData = cipher.doFinal(Base64.getDecoder().decode(text.substring(dotIndex + 1)));
            return new String(textData, StandardCharsets.UTF_8);
        } else {
            throw new IllegalArgumentException(privateKey.getClass().getName() + " is not supported");
        }
    }

}
