package com.senior.cyber.pki.api.root.controller;

import com.senior.cyber.pki.common.dto.SubordinateGenerateRequest;
import com.senior.cyber.pki.common.dto.SubordinateGenerateResponse;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.service.SubordinateService;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.joda.time.LocalDate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Date;

@RestController
public class SubordinateController {

    private static final Logger LOGGER = LoggerFactory.getLogger(SubordinateController.class);

    @Autowired
    protected SubordinateService subordinateService;

    @Value("${api.crl}")
    protected String crlApi;

    @Value("${api.ocsp}")
    protected String ocspApi;

    @Value("${api.x509}")
    protected String x509Api;

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    /**
     * for root ca to issue subordinate ca
     *
     * @param httpRequest
     * @return
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     * @throws ApduException
     * @throws ApplicationNotAvailableException
     * @throws BadResponseException
     */
    @RequestMapping(path = "/subordinate/generate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SubordinateGenerateResponse> subordinateGenerate(RequestEntity<SubordinateGenerateRequest> httpRequest) throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, ApduException, ApplicationNotAvailableException, BadResponseException {
        SubordinateGenerateRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuer().getCertificateId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "issuer certificate is not found"));
        if (issuerCertificate.getStatus() == CertificateStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "issuer certificate have been revoked");
        }
        if (issuerCertificate.getType() != CertificateTypeEnum.ROOT_CA) {
            LOGGER.info("issuer certificate type is {}", issuerCertificate.getType());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "issuer certificate is not type of [" + CertificateTypeEnum.ROOT_CA + "]");
        }
        Date now = LocalDate.now().toDate();
        if (issuerCertificate.getValidFrom().after(now) || issuerCertificate.getValidUntil().before(now)) {
            LOGGER.info("issuer certificate valid from [{}] valid until [{}] and now [{}]", DateFormatUtils.ISO_8601_EXTENDED_DATE_FORMAT.format(issuerCertificate.getValidFrom()), DateFormatUtils.ISO_8601_EXTENDED_DATE_FORMAT.format(issuerCertificate.getValidUntil()), DateFormatUtils.ISO_8601_EXTENDED_DATE_FORMAT.format(now));
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "issuer certificate has expired");
        }

        Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "issuer key is not found"));
        if (issuerKey.getStatus() == KeyStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "issuer key have been revoked");
        }

        Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "key is not found"));
        if (key.getStatus() == KeyStatusEnum.Revoked) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "key have been revoked");
        }

        String serial = String.format("%012X", issuerCertificate.getSerial());

        SubordinateGenerateResponse response = this.subordinateService.subordinateGenerate(request, this.crlApi + "/" + serial + ".crl", this.ocspApi + "/" + serial, this.x509Api + "/" + serial + ".der");
        return ResponseEntity.ok(response);
    }

}
