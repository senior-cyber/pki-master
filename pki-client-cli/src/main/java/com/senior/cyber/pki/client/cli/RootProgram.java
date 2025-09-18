package com.senior.cyber.pki.client.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.client.cli.utils.ClientUtils;
import com.senior.cyber.pki.client.cli.utils.KeyUtils;
import com.senior.cyber.pki.common.dto.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;

@Slf4j
public class RootProgram {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void main(String[] args) throws Throwable {
//        KeyUtils.yubicoClientGenerate("9a", ClientProgram.PIN, "2048", ClientProgram.MANAGEMENT_KEY, "RSA", "23275988", "k.socheat@khmer.name", "root-key.json");
//
//        Subject rootSubject = Subject.create();
//        rootSubject.setLocality("Phnom Penh");
//        rootSubject.setProvince("Kandal");
//        rootSubject.setCountry("KH");
//        rootSubject.setEmailAddress("k.socheat@khmer.name");
//        rootSubject.setCommonName("Cambodia National RootCA");
//        rootSubject.setOrganization("Ministry of Post and Telecom");
//        rootSubject.setOrganizationalUnit("Digital Government Committee");
//
//        Key _key = MAPPER.readValue(FileUtils.readFileToString(new File("root-key.json"), StandardCharsets.UTF_8), Key.class);
//
//        QueueRequestRequest request = QueueRequestRequest.create();
//        request.setSubject(rootSubject);
//        request.setKeyId(_key.getKeyId());
//        request.setType(CertificateTypeEnum.ROOT_CA);
//        request.setIssuerKeyId(_key.getKeyId());
//        request.setIssuerCertificateId(null);
//
//        var response = ClientUtils.queueRequest(request);

        var p = ClientUtils.queueSearch(QueueSearchRequest.builder().keyId("702df00a-58ae-477f-87ef-bfe7e4eb51a5").build());

        System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(p));
        // 33137f6b-090c-449d-beb1-622cd429dd8e
//        FileUtils.write(new File("root-subject.json"), ClientProgram.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(rootSubject), StandardCharsets.UTF_8);
//
//        RootUtils.rootGenerateYubicoClientSign("root-key.json", "root-subject.json", "root-ca.json");
        System.exit(0);
    }

}
