package com.senior.cyber.pki.client.cli;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.senior.cyber.pki.client.cli.utils.KeyUtils;
import com.senior.cyber.pki.client.cli.utils.RootUtils;
import com.senior.cyber.pki.common.dto.CertificateTypeEnum;
import com.senior.cyber.pki.common.dto.QueueRequestRequest;
import com.senior.cyber.pki.common.dto.Subject;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;

@Slf4j
public class RootProgram {

    public static void main(String[] args) throws Throwable {
        KeyUtils.yubicoClientGenerate("9a", ClientProgram.PIN, "2048", ClientProgram.MANAGEMENT_KEY, "RSA", "23275988", "k.socheat@khmer.name", "root-key.json");

        Subject rootSubject = Subject.create();
        rootSubject.setLocality("Phnom Penh");
        rootSubject.setProvince("Kandal");
        rootSubject.setCountry("KH");
        rootSubject.setEmailAddress("k.socheat@khmer.name");
        rootSubject.setCommonName("Cambodia National RootCA");
        rootSubject.setOrganization("Ministry of Post and Telecom");
        rootSubject.setOrganizationalUnit("Digital Government Committee");

        QueueRequestRequest request = QueueRequestRequest.create();
        request.setSubject(rootSubject);
        request.setKeyId("");
        request.setType(CertificateTypeEnum.ROOT_CA);
        request.setIssuerKeyId("");
        request.setIssuerCertificateId("");


        FileUtils.write(new File("root-subject.json"), ClientProgram.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(rootSubject), StandardCharsets.UTF_8);

        RootUtils.rootGenerateYubicoClientSign("root-key.json", "root-subject.json", "root-ca.json");
        System.exit(0);
    }

}
