package com.senior.cyber.pki.web.controller;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.senior.cyber.frmk.common.x509.PublicKeyUtils;
import com.senior.cyber.pki.dao.entity.Key;
import com.senior.cyber.pki.web.configuration.SslConfiguration;
import com.senior.cyber.pki.web.repository.KeyRepository;
import com.senior.cyber.pki.web.utility.Crypto;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Optional;

@RestController
@RequestMapping(path = "/key")
public class KeyController {

    @Autowired
    protected KeyRepository keyRepository;

    @Autowired
    protected Crypto crypto;

    @Autowired
    protected SslConfiguration sslConfiguration;

    protected static KeyPair keyPair;

    protected static KeyPair lookupKeyPair(SslConfiguration sslConfiguration) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (keyPair != null) {
            return keyPair;
        }
        KeyStore keyStore = KeyStore.getInstance(sslConfiguration.getKeyStoreType());
        String keyPassword = null;
        if (sslConfiguration.getKeyPassword() == null || "".equals(sslConfiguration.getKeyPassword())) {
            keyPassword = sslConfiguration.getKeyStorePassword();
        } else {
            keyPassword = sslConfiguration.getKeyPassword();
        }
        try (InputStream stream = new ByteArrayInputStream(IOUtils.toByteArray(FileUtils.openInputStream(sslConfiguration.getKeyStore())))) {
            keyStore.load(stream, sslConfiguration.getKeyStorePassword().toCharArray());
        }
        String keyAlias = null;
        if (sslConfiguration.getKeyAlias() == null || "".equals(sslConfiguration.getKeyAlias())) {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                keyAlias = aliases.nextElement();
                break;
            }
        } else {
            keyAlias = sslConfiguration.getKeyAlias();
        }
        Certificate certificate = keyStore.getCertificate(keyAlias);
        PublicKey publicKey = PublicKeyUtils.read(PublicKeyUtils.write(certificate.getPublicKey()));
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());
        keyPair = new KeyPair(publicKey, privateKey);
        return keyPair;
    }

    protected static KeyPair lookupKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        if (keyPair != null) {
            return keyPair;
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(256);
        keyPair = generator.generateKeyPair();
        return keyPair;
    }

    @RequestMapping(path = "/info", method = RequestMethod.GET, produces = "text/plain")
    public ResponseEntity<String> info(HttpServletRequest request) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException, NoSuchProviderException {
        KeyPair keyPair = null;
        if (request.isSecure()) {
            keyPair = lookupKeyPair(sslConfiguration);
        } else {
            keyPair = lookupKeyPair();
        }
        return ResponseEntity.ok(PublicKeyUtils.write(keyPair.getPublic()));
    }

    @RequestMapping(path = "/{clientId}/encrypt", method = RequestMethod.POST)
    public ResponseEntity<byte[]> encrypt(
            @RequestHeader("Client-Secret") String clientSecret,
            @RequestHeader(value = "Public-Key") String clientPublicKeyText,
            @PathVariable("clientId") String clientId,
            HttpServletRequest request
    ) throws IOException, GeneralSecurityException {
        KeyPair keyPair = null;
        if (request.isSecure()) {
            keyPair = lookupKeyPair(sslConfiguration);
        } else {
            keyPair = lookupKeyPair();
        }

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey clientPublicKey = PublicKeyUtils.read(crypto.decrypt(privateKey, clientPublicKeyText));
        SecretKey secret = crypto.lookupKeyAgreement((ECPrivateKey) privateKey, (ECPublicKey) clientPublicKey);

        Optional<Key> optionalKey = keyRepository.findByClientId(clientId);
        Key key = optionalKey.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(clientSecret), "AES");
        SecretKeyFactory factory = SecretKeyFactory.getInstance("AES", BouncyCastleProvider.PROVIDER_NAME);
        SecretKey secretKey = factory.generateSecret(secretKeySpec);

        String kekJson = crypto.decrypt(secretKey, key.getKek());
        KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withString(kekJson));
        Aead aead = handle.getPrimitive(Aead.class);

        String requestCipherText = IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8);
        String requestPlainText = crypto.decrypt(secret, requestCipherText);
        byte[] requestPlainData = Base64.getDecoder().decode(requestPlainText);

        byte[] associatedData = "".getBytes(StandardCharsets.UTF_8);
        byte[] responsePlainData = aead.encrypt(requestPlainData, associatedData);
        String responsePlainText = Base64.getEncoder().encodeToString(responsePlainData);
        String responseCipherText = this.crypto.encrypt(secret, responsePlainText);
        return ResponseEntity.ok(responseCipherText.getBytes(StandardCharsets.UTF_8));
    }

    @RequestMapping(path = "/{clientId}/decrypt", method = RequestMethod.POST)
    public ResponseEntity<byte[]> decrypt(
            @RequestHeader("Client-Secret") String clientSecret,
            @RequestHeader(value = "Public-Key") String clientPublicKeyText,
            @PathVariable("clientId") String clientId,
            HttpServletRequest request
    ) throws IOException, GeneralSecurityException {
        KeyPair keyPair = null;
        if (request.isSecure()) {
            keyPair = lookupKeyPair(sslConfiguration);
        } else {
            keyPair = lookupKeyPair();
        }

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey clientPublicKey = PublicKeyUtils.read(crypto.decrypt(privateKey, clientPublicKeyText));
        SecretKey secret = crypto.lookupKeyAgreement((ECPrivateKey) privateKey, (ECPublicKey) clientPublicKey);

        Optional<Key> optionalKey = keyRepository.findByClientId(clientId);
        Key key = optionalKey.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(clientSecret), "AES");
        SecretKeyFactory factory = SecretKeyFactory.getInstance("AES", BouncyCastleProvider.PROVIDER_NAME);
        SecretKey secretKey = factory.generateSecret(secretKeySpec);

        String kekJson = crypto.decrypt(secretKey, key.getKek());

        KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withString(kekJson));
        Aead aead = handle.getPrimitive(Aead.class);

        String requestCipherText = IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8);
        String requestPlainText = crypto.decrypt(secret, requestCipherText);
        byte[] requestPlainData = Base64.getDecoder().decode(requestPlainText);

        byte[] associatedData = "".getBytes(StandardCharsets.UTF_8);
        byte[] responsePlainData = aead.decrypt(requestPlainData, associatedData);
        String responsePlainText = Base64.getEncoder().encodeToString(responsePlainData);
        String responseCipherText = this.crypto.encrypt(secret, responsePlainText);
        return ResponseEntity.ok(responseCipherText.getBytes(StandardCharsets.UTF_8));
    }

}
