package com.senior.cyber.pki.web.controller;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.senior.cyber.frmk.common.pki.PublicKeyUtils;
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

    @RequestMapping(path = "/info", method = RequestMethod.GET, produces = "text/plain")
    public ResponseEntity<String> info(HttpServletRequest request) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {
        if (request.isSecure()) {
            KeyStore keyStore = KeyStore.getInstance(sslConfiguration.getKeyStoreType());
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
            return ResponseEntity.ok(PublicKeyUtils.write(publicKey));
        } else {
            throw new java.lang.UnsupportedOperationException("https configuration is required");
        }
    }

    @RequestMapping(path = "/{clientId}/encrypt", method = RequestMethod.POST)
    public ResponseEntity<byte[]> encrypt(
            @RequestHeader("Client-Secret") String clientSecret,
            @RequestHeader(value = "Public-Key", required = false) String publicKey,
            @PathVariable("clientId") String clientId,
            HttpServletRequest request
    ) throws IOException, GeneralSecurityException {
        if (request.isSecure() && (publicKey == null || "".equals(publicKey))) {
            throw new java.lang.IllegalArgumentException("Public-Key is required");
        }
        if (!request.isSecure()) {
            Optional<Key> optionalKey = keyRepository.findByClientId(clientId);
            Key key = optionalKey.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

            SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(clientSecret), "AES");
            SecretKeyFactory factory = SecretKeyFactory.getInstance("AES", BouncyCastleProvider.PROVIDER_NAME);
            SecretKey secretKey = factory.generateSecret(secretKeySpec);

            String kekJson = crypto.decrypt(secretKey, key.getKek());
            KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withString(kekJson));
            Aead aead = handle.getPrimitive(Aead.class);

            byte[] requestPlainData = IOUtils.toByteArray(request.getInputStream());
            byte[] associatedData = "".getBytes(StandardCharsets.UTF_8);
            byte[] responsePlainData = aead.encrypt(requestPlainData, associatedData);
            return ResponseEntity.ok(responsePlainData);
        } else {
            KeyStore keyStore = KeyStore.getInstance(sslConfiguration.getKeyStoreType());
            try (InputStream stream = FileUtils.openInputStream(sslConfiguration.getKeyStore())) {
                keyStore.load(stream, sslConfiguration.getKeyStorePassword().toCharArray());
            }
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(sslConfiguration.getKeyAlias(), sslConfiguration.getKeyPassword().toCharArray());
            PublicKey clientPublicKey = PublicKeyUtils.read(crypto.decrypt(privateKey, publicKey));
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
    }

    @RequestMapping(path = "/{clientId}/decrypt", method = RequestMethod.POST)
    public ResponseEntity<byte[]> decrypt(
            @RequestHeader("Client-Secret") String clientSecret,
            @RequestHeader(value = "Public-Key", required = false) String publicKey,
            @PathVariable("clientId") String clientId,
            HttpServletRequest request
    ) throws IOException, GeneralSecurityException {
        if (request.isSecure() && (publicKey == null || "".equals(publicKey))) {
            throw new java.lang.IllegalArgumentException("Public-Key is required");
        }
        if (!request.isSecure()) {
            Optional<Key> optionalKey = keyRepository.findByClientId(clientId);
            Key key = optionalKey.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

            SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(clientSecret), "AES");
            SecretKeyFactory factory = SecretKeyFactory.getInstance("AES", BouncyCastleProvider.PROVIDER_NAME);
            SecretKey secretKey = factory.generateSecret(secretKeySpec);

            String kekJson = crypto.decrypt(secretKey, key.getKek());

            KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withString(kekJson));
            Aead aead = handle.getPrimitive(Aead.class);

            byte[] requestPlainData = IOUtils.toByteArray(request.getInputStream());
            byte[] associatedData = "".getBytes(StandardCharsets.UTF_8);
            byte[] responsePlainData = aead.decrypt(requestPlainData, associatedData);
            return ResponseEntity.ok(responsePlainData);
        } else {
            KeyStore keyStore = KeyStore.getInstance(sslConfiguration.getKeyStoreType());
            try (InputStream stream = FileUtils.openInputStream(sslConfiguration.getKeyStore())) {
                keyStore.load(stream, sslConfiguration.getKeyStorePassword().toCharArray());
            }
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(sslConfiguration.getKeyAlias(), sslConfiguration.getKeyPassword().toCharArray());
            PublicKey clientPublicKey = PublicKeyUtils.read(crypto.decrypt(privateKey, publicKey));
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

}
