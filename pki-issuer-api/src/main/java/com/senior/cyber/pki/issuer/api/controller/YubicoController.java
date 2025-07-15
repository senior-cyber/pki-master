package com.senior.cyber.pki.issuer.api.controller;

import com.senior.cyber.pki.common.dto.JcaRootGenerateRequest;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteWatchdog;
import org.apache.commons.exec.PumpStreamHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

@RestController
public class YubicoController {

    private static final Logger LOGGER = LoggerFactory.getLogger(YubicoController.class);

    @RequestMapping(path = "/yubico/info", method = RequestMethod.GET, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> rootInfo(RequestEntity<JcaRootGenerateRequest> httpRequest) throws IOException {
        CommandLine cmd = new CommandLine("/usr/bin/pkcs11-tool");
        cmd.addArgument("-L");

        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        PumpStreamHandler streams = new PumpStreamHandler(stdout, null);

        ExecuteWatchdog watchdog = ExecuteWatchdog.builder()
                .setTimeout(Duration.ofMinutes(1))
                .get();

        DefaultExecutor exec = DefaultExecutor.builder()
                .get();
        exec.setWatchdog(watchdog);
        exec.setStreamHandler(streams);
        exec.setExitValue(0);

        int exit = exec.execute(cmd);
        LOGGER.info("exit [{}]", exit);

        String out = stdout.toString(StandardCharsets.UTF_8);

        return ResponseEntity.ok(out);
    }

}
