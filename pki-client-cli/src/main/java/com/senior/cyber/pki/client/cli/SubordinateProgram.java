package com.senior.cyber.pki.client.cli;

import com.senior.cyber.pki.client.cli.utils.ClientUtils;
import com.senior.cyber.pki.client.cli.utils.KeyUtils;
import com.senior.cyber.pki.client.cli.utils.SubordinateUtils;
import com.senior.cyber.pki.common.dto.ServerInfoResponse;
import com.senior.cyber.pki.common.dto.Subject;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;

@Slf4j
public class SubordinateProgram {

    public static void main(String[] args) throws Throwable {
        KeyUtils.yubicoClientGenerate("9c", ClientProgram.PIN, "2048", ClientProgram.MANAGEMENT_KEY, "RSA", "23275988", "k.socheat@khmer.name", "subordinate-key.json");

        ServerInfoResponse response = ClientUtils.serverInfoV1();
        String crlApi = response.getApiCrl();
        String ocspApi = response.getApiOcsp();
        String x509Api = response.getApiX509();

        Subject subordinateSubject = Subject.create();
        subordinateSubject.setLocality("Phnom Penh");
        subordinateSubject.setProvince("Kandal");
        subordinateSubject.setCountry("KH");
        subordinateSubject.setEmailAddress("k.socheat@khmer.name");
        subordinateSubject.setCommonName("Cambodia National SubordinateCA");
        subordinateSubject.setOrganization("Ministry of Post and Telecom");
        subordinateSubject.setOrganizationalUnit("Digital Government Committee");

        FileUtils.write(new File("subordinate-subject.json"), ClientProgram.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(subordinateSubject), StandardCharsets.UTF_8);

        SubordinateUtils.subordinateGenerate(crlApi, ocspApi, x509Api, "root-ca.json", "subordinate-key.json", "subordinate-subject.json", "subordinate-ca.json");
    }

}
