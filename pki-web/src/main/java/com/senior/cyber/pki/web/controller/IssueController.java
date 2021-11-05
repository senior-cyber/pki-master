package com.senior.cyber.pki.web.controller;

import com.google.gson.Gson;
import com.senior.cyber.frmk.common.pki.CertificateUtils;
import com.senior.cyber.frmk.common.pki.PrivateKeyUtils;
import com.senior.cyber.pki.dao.entity.*;
import com.senior.cyber.pki.web.configuration.PkiApiConfiguration;
import com.senior.cyber.pki.web.dto.*;
import com.senior.cyber.pki.web.repository.*;
import com.senior.cyber.pki.web.utility.*;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.EmailValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.Days;
import org.joda.time.LocalDate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping(path = "/issue")
public class IssueController {

    @Autowired
    protected Gson gson;

    @Autowired
    protected RootRepository rootRepository;

    @Autowired
    protected UserRepository userRepository;

    @Autowired
    protected IbanRepository ibanRepository;

    @Autowired
    protected IntermediateRepository intermediateRepository;

    @Autowired
    protected PkiApiConfiguration pkiApiConfiguration;

    @Autowired
    protected CertificateRepository certificateRepository;

    @RequestMapping(path = "/root", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> root(HttpServletRequest request) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException {
        User user = UserUtility.authenticate(request);

        SubjectDto subjectDto = gson.fromJson(IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8), SubjectDto.class);
        if (subjectDto.getCommonName() == null || "".equals(subjectDto.getCommonName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "commonName is required");
        } else {
            Optional<Root> optionalRoot = rootRepository.findByCommonNameAndUserAndStatus(subjectDto.getCommonName(), user, "Good");
            if (optionalRoot.isPresent()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "commonName \"" + subjectDto.getCommonName() + "\" is not available");
            }
        }

        if (subjectDto.getOrganization() == null || "".equals(subjectDto.getOrganization())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "organization is required");
        }

        if (subjectDto.getCountry() == null || "".equals(subjectDto.getCountry())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "country is required");
        } else {
            Optional<Iban> optionalIban = ibanRepository.findByAlpha2Code(subjectDto.getCountry());
            if (optionalIban.isPresent()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "country \"" + subjectDto.getCountry() + "\" is not found");
            }
        }

        if (subjectDto.getEmailAddress() != null && !"".equals(subjectDto.getEmailAddress())) {
            if (!EmailValidator.getInstance().isValid(subjectDto.getEmailAddress())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, subjectDto.getEmailAddress() + " is not valid");
            }
        }

        LocalDate validFrom = null;
        if (subjectDto.getValidFrom() == null) {
            validFrom = LocalDate.now();
        } else {
            validFrom = LocalDate.fromDateFields(subjectDto.getValidFrom());
        }
        LocalDate validUntil = null;
        if (subjectDto.getValidUtil() == null) {
            validUntil = LocalDate.now().plusYears(5);
        } else {
            validUntil = LocalDate.fromDateFields(subjectDto.getValidUtil());
        }
        if (validFrom.isAfter(validUntil)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "validFrom is after validUntil");
        }

        KeyPair key = KeyPairUtility.generate();

        X500Name subject = SubjectUtility.generate(subjectDto.getCountry(), subjectDto.getOrganization(), subjectDto.getOrganizationalUnit(), subjectDto.getCommonName(), subjectDto.getLocalityName(), subjectDto.getStateOrProvinceName(), subjectDto.getEmailAddress());

        PKCS10CertificationRequest csr = CertificationSignRequestUtility.generate(key.getPrivate(), key.getPublic(), subject);

        long serial = System.currentTimeMillis();

        CertificateRequestDto requestDto = new CertificateRequestDto();
        requestDto.setBasicConstraints(true);
        requestDto.setCsr(csr);
        requestDto.setIssuerPrivateKey(key.getPrivate());
        requestDto.setDuration(Days.daysBetween(validFrom, validUntil).getDays());
        requestDto.setSerial(serial);

        requestDto.setBasicConstraintsCritical(true);
        requestDto.setKeyUsageCritical(true);

        requestDto.setSubjectAlternativeNameCritical(false);

        requestDto.setSubjectKeyIdentifierCritical(false);
        requestDto.setAuthorityKeyIdentifierCritical(false);
        requestDto.setAuthorityInfoAccessCritical(false);

        requestDto.setExtendedKeyUsageCritical(false);

        requestDto.setcRLDistributionPointsCritical(false);

        X509Certificate certificate = CertificateUtility.generate(requestDto);

        Root root = new Root();

        root.setSerial(serial);

        root.setLocalityName(subjectDto.getLocalityName());
        root.setStateOrProvinceName(subjectDto.getStateOrProvinceName());
        root.setCountryCode(subjectDto.getCountry());
        root.setCommonName(subjectDto.getCommonName());
        root.setOrganization(subjectDto.getOrganization());
        root.setOrganizationalUnit(subjectDto.getOrganizationalUnit());
        root.setEmailAddress(subjectDto.getEmailAddress());

        root.setCertificate(CertificateUtils.write(certificate));
        root.setPrivateKey(PrivateKeyUtils.write(key.getPrivate()));

        root.setValidFrom(validFrom.toDate());
        root.setValidUntil(validUntil.toDate());

        root.setStatus("Good");

        root.setUser(user);

        rootRepository.save(root);

        return ResponseEntity.ok(root.getCertificate());
    }

    @RequestMapping(path = "/intermediate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = "application/zip")
    public ResponseEntity<byte[]> intermediate(HttpServletRequest request) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException {
        User user = UserUtility.authenticate(request);

        SubjectDto subjectDto = gson.fromJson(IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8), SubjectDto.class);
        if (subjectDto.getCommonName() == null || "".equals(subjectDto.getCommonName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "commonName is required");
        } else {
            Optional<Root> optionalRoot = rootRepository.findByCommonNameAndUserAndStatus(subjectDto.getCommonName(), user, "Good");
            if (optionalRoot.isPresent()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "commonName \"" + subjectDto.getCommonName() + "\" is not available");
            }
        }

        if (subjectDto.getOrganization() == null || "".equals(subjectDto.getOrganization())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "organization is required");
        }

        if (subjectDto.getCountry() == null || "".equals(subjectDto.getCountry())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "country is required");
        } else {
            Optional<Iban> optionalIban = ibanRepository.findByAlpha2Code(subjectDto.getCountry());
            if (optionalIban.isPresent()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "country \"" + subjectDto.getCountry() + "\" is not found");
            }
        }

        if (subjectDto.getEmailAddress() != null && !"".equals(subjectDto.getEmailAddress())) {
            if (!EmailValidator.getInstance().isValid(subjectDto.getEmailAddress())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, subjectDto.getEmailAddress() + " is not valid");
            }
        }

        LocalDate validFrom = null;
        if (subjectDto.getValidFrom() == null) {
            validFrom = LocalDate.now();
        } else {
            validFrom = LocalDate.fromDateFields(subjectDto.getValidFrom());
        }
        LocalDate validUntil = null;
        if (subjectDto.getValidUtil() == null) {
            validUntil = LocalDate.now().plusYears(3);
        } else {
            validUntil = LocalDate.fromDateFields(subjectDto.getValidUtil());
        }
        if (validFrom.isAfter(validUntil)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "validFrom is after validUntil");
        }

        Root root = null;
        if (subjectDto.getRootCommonName() == null || "".equals(subjectDto.getRootCommonName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "rootCommonName is required");
        } else {
            Optional<Root> optionalRoot = rootRepository.findByCommonNameAndUserAndStatus(subjectDto.getRootCommonName(), user, "Good");
            root = optionalRoot.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, subjectDto.getRootCommonName() + " is not valid"));
        }

        long serial = System.currentTimeMillis();

        String httpAddress = pkiApiConfiguration.getAddress();

        KeyPair key = KeyPairUtility.generate();

        X500Name subject = SubjectUtility.generate(subjectDto.getCountry(), subjectDto.getOrganization(), subjectDto.getOrganizationalUnit(), subjectDto.getCommonName(), subjectDto.getLocalityName(), subjectDto.getStateOrProvinceName(), subjectDto.getEmailAddress());

        PKCS10CertificationRequest csr = CertificationSignRequestUtility.generate(key.getPrivate(), key.getPublic(), subject);

        CertificateRequestDto requestDto = new CertificateRequestDto();
        requestDto.setBasicConstraints(true);
        requestDto.setCsr(csr);
        requestDto.setIssuerCertificate(CertificateUtils.read(root.getCertificate()));
        requestDto.setIssuerPrivateKey(PrivateKeyUtils.read(root.getPrivateKey()));
        requestDto.setDuration(Days.daysBetween(validFrom, validUntil).getDays());
        requestDto.setSerial(serial);

        requestDto.getCRLDistributionPoints().add(new GeneralNameDto(httpAddress + "/api/pki/crl/root/" + root.getSerial() + ".crl"));
        requestDto.getAuthorityInfoAccess().add(new GeneralNameDto(GeneralNameTypeEnum.OCSP, httpAddress + "/api/pki/ocsp/root/" + root.getSerial()));
        requestDto.getAuthorityInfoAccess().add(new GeneralNameDto(GeneralNameTypeEnum.CA, httpAddress + "/api/pki/root/" + root.getSerial() + ".der"));

        requestDto.setBasicConstraintsCritical(true);
        requestDto.setKeyUsageCritical(true);

        requestDto.setSubjectAlternativeNameCritical(false);

        requestDto.setSubjectKeyIdentifierCritical(false);
        requestDto.setAuthorityKeyIdentifierCritical(false);
        requestDto.setAuthorityInfoAccessCritical(false);

        requestDto.setExtendedKeyUsageCritical(false);

        requestDto.setcRLDistributionPointsCritical(false);

        X509Certificate certificate = CertificateUtility.generate(requestDto);

        Intermediate intermediate = new Intermediate();

        intermediate.setSerial(serial);

        intermediate.setLocalityName(subjectDto.getLocalityName());
        intermediate.setStateOrProvinceName(subjectDto.getStateOrProvinceName());
        intermediate.setCountryCode(subjectDto.getCountry());
        intermediate.setCommonName(subjectDto.getCommonName());
        intermediate.setOrganization(subjectDto.getOrganization());
        intermediate.setOrganizationalUnit(subjectDto.getOrganizationalUnit());
        intermediate.setEmailAddress(subjectDto.getEmailAddress());

        intermediate.setCertificate(CertificateUtils.write(certificate));
        intermediate.setPrivateKey(PrivateKeyUtils.write(key.getPrivate()));

        intermediate.setValidFrom(validFrom.toDate());
        intermediate.setValidUntil(validUntil.toDate());

        intermediate.setStatus("Good");

        intermediate.setRoot(root);

        intermediate.setUser(user);
        intermediateRepository.save(intermediate);

        String name = StringUtils.replace(intermediate.getCommonName(), " ", "_");

        ByteArrayOutputStream data = new ByteArrayOutputStream();
        ZipArchiveOutputStream zipArchiveOutputStream = new ZipArchiveOutputStream(data);

        {

            String changeit = "changeit";

            StringBuffer buffer = new StringBuffer();

            buffer.append("# Installation Instructions for SpringBoot").append("\n");
            buffer.append("====================================================================================").append("\n");
            buffer.append("openssl pkcs12 -nokeys -in " + name + ".crt -export -out " + name + ".p12 -passout pass:" + changeit).append("\n");

            buffer.append("\n");
            buffer.append("# Installation Instructions for SpringBoot").append("\n");
            buffer.append("====================================================================================").append("\n");
            buffer.append("server.ssl.enabled=true").append("\n");
            buffer.append("server.ssl.client-auth=need").append("\n");
            buffer.append("server.ssl.trust-store=/your/path/to/" + name + ".p12").append("\n");
            buffer.append("server.ssl.trust-store-type=PKCS12").append("\n");
            buffer.append("server.ssl.trust-store-password=" + changeit).append("\n");

            String crt = buffer.toString();
            ZipArchiveEntry caChainEntry = new ZipArchiveEntry("README.txt");
            caChainEntry.setSize(crt.getBytes(StandardCharsets.UTF_8).length);
            zipArchiveOutputStream.putArchiveEntry(caChainEntry);
            zipArchiveOutputStream.write(crt.getBytes(StandardCharsets.UTF_8));
            zipArchiveOutputStream.closeArchiveEntry();
        }

        {
            ZipArchiveEntry certificateEntry = new ZipArchiveEntry(name + ".crt");
            certificateEntry.setSize(intermediate.getCertificate().getBytes(StandardCharsets.UTF_8).length);
            zipArchiveOutputStream.putArchiveEntry(certificateEntry);
            zipArchiveOutputStream.write(intermediate.getCertificate().getBytes(StandardCharsets.UTF_8));
            zipArchiveOutputStream.closeArchiveEntry();
        }

        {
            ZipArchiveEntry privateKeyEntry = new ZipArchiveEntry(name + ".pem");
            privateKeyEntry.setSize(intermediate.getPrivateKey().getBytes(StandardCharsets.UTF_8).length);
            zipArchiveOutputStream.putArchiveEntry(privateKeyEntry);
            zipArchiveOutputStream.write(intermediate.getPrivateKey().getBytes(StandardCharsets.UTF_8));
            zipArchiveOutputStream.closeArchiveEntry();
        }

        zipArchiveOutputStream.close();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "inline; filename=\"" + intermediate.getId() + ".zip\"");
        return ResponseEntity.ok().headers(headers).body(data.toByteArray());
    }

    @RequestMapping(path = "/certificate", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = "application/zip")
    public ResponseEntity<byte[]> certificate(HttpServletRequest request) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException {
        User user = UserUtility.authenticate(request);

        SubjectDto subjectDto = gson.fromJson(IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8), SubjectDto.class);
        if (subjectDto.getCommonName() == null || "".equals(subjectDto.getCommonName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "commonName is required");
        } else {
            Optional<Root> optionalRoot = rootRepository.findByCommonNameAndUserAndStatus(subjectDto.getCommonName(), user, "Good");
            if (optionalRoot.isPresent()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "commonName \"" + subjectDto.getCommonName() + "\" is not available");
            }
        }

        if (subjectDto.getOrganization() == null || "".equals(subjectDto.getOrganization())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "organization is required");
        }

        if (subjectDto.getCountry() == null || "".equals(subjectDto.getCountry())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "country is required");
        } else {
            Optional<Iban> optionalIban = ibanRepository.findByAlpha2Code(subjectDto.getCountry());
            if (optionalIban.isPresent()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "country \"" + subjectDto.getCountry() + "\" is not found");
            }
        }

        if (subjectDto.getEmailAddress() != null && !"".equals(subjectDto.getEmailAddress())) {
            if (!EmailValidator.getInstance().isValid(subjectDto.getEmailAddress())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, subjectDto.getEmailAddress() + " is not valid");
            }
        }

        LocalDate validFrom = null;
        if (subjectDto.getValidFrom() == null) {
            validFrom = LocalDate.now();
        } else {
            validFrom = LocalDate.fromDateFields(subjectDto.getValidFrom());
        }
        LocalDate validUntil = null;
        if (subjectDto.getValidUtil() == null) {
            validUntil = LocalDate.now().plusYears(1);
        } else {
            validUntil = LocalDate.fromDateFields(subjectDto.getValidUtil());
        }
        if (validFrom.isAfter(validUntil)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "validFrom is after validUntil");
        }

        Intermediate intermediate = null;
        if (subjectDto.getIntermediateCommonName() == null || "".equals(subjectDto.getIntermediateCommonName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "intermediateCommonName is required");
        } else {
            Optional<Intermediate> optionalIntermediate = intermediateRepository.findByCommonNameAndUserAndStatus(subjectDto.getIntermediateCommonName(), user, "Good");
            intermediate = optionalIntermediate.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, subjectDto.getIntermediateCommonName() + " is not valid"));
        }

        long serial = System.currentTimeMillis();

        String httpAddress = pkiApiConfiguration.getAddress();

        KeyPair key = KeyPairUtility.generate();

        X500Name subject = SubjectUtility.generate(subjectDto.getCountry(), subjectDto.getOrganization(), subjectDto.getOrganizationalUnit(), subjectDto.getCommonName(), subjectDto.getLocalityName(), subjectDto.getStateOrProvinceName(), subjectDto.getEmailAddress());

        PKCS10CertificationRequest csr = CertificationSignRequestUtility.generate(key.getPrivate(), key.getPublic(), subject);

        CertificateRequestDto requestDto = new CertificateRequestDto();
        requestDto.setBasicConstraints(false);
        requestDto.setCsr(csr);
        requestDto.setIssuerCertificate(CertificateUtils.read(intermediate.getCertificate()));
        requestDto.setIssuerPrivateKey(PrivateKeyUtils.read(intermediate.getPrivateKey()));
        requestDto.setDuration(Days.daysBetween(validFrom, validUntil).getDays());
        requestDto.setSerial(serial);

        requestDto.setBasicConstraintsCritical(true);
        requestDto.setKeyUsageCritical(true);

        requestDto.setSubjectAlternativeNameCritical(false);

        requestDto.setSubjectKeyIdentifierCritical(false);
        requestDto.setAuthorityKeyIdentifierCritical(false);
        requestDto.setAuthorityInfoAccessCritical(false);

        requestDto.setExtendedKeyUsageCritical(false);

        requestDto.setcRLDistributionPointsCritical(false);

        requestDto.getCRLDistributionPoints().add(new GeneralNameDto(httpAddress + "/api/pki/crl/intermediate/" + intermediate.getSerial() + ".crl"));
        requestDto.getAuthorityInfoAccess().add(new GeneralNameDto(GeneralNameTypeEnum.OCSP, httpAddress + "/api/pki/ocsp/intermediate/" + intermediate.getSerial()));
        requestDto.getAuthorityInfoAccess().add(new GeneralNameDto(GeneralNameTypeEnum.CA, httpAddress + "/api/pki/intermediate/" + intermediate.getSerial() + ".der"));

        List<String> subjectAltName = new ArrayList<>();
        if (subjectDto.getSubjectAltNames() != null && !subjectDto.getSubjectAltNames().isEmpty()) {
            for (String temp : subjectDto.getSubjectAltNames()) {
                temp = StringUtils.trimToEmpty(temp);
                if (!"".equals(temp)) {
                    if (!subjectAltName.contains("IP:" + temp) && !subjectAltName.contains("DNS:" + temp)) {
                        if (InetAddressValidator.getInstance().isValid(temp)) {
                            subjectAltName.add("IP:" + temp);
                            requestDto.getSubjectAlternativeName().add(new GeneralNameDto(GeneralNameTagEnum.IP, temp));
                        } else if (DomainValidator.getInstance().isValid(temp)) {
                            subjectAltName.add("DNS:" + temp);
                            requestDto.getSubjectAlternativeName().add(new GeneralNameDto(GeneralNameTagEnum.DNS, temp));
                        } else {
                            if (temp.matches("[A-Za-z0-9._-]+")) {
                                subjectAltName.add("DNS:" + temp);
                                requestDto.getSubjectAlternativeName().add(new GeneralNameDto(GeneralNameTagEnum.DNS, temp));
                            } else {
                                if (temp.startsWith("*.")) {
                                    if (DomainValidator.getInstance().isValid(temp.substring(2))) {
                                        subjectAltName.add("DNS:" + temp);
                                    } else {
                                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, temp + " is not valid");
                                    }
                                } else {
                                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, temp + " is not valid");
                                }
                            }
                        }
                    }
                }
            }
        }

        X509Certificate x509Certificate = CertificateUtility.generate(requestDto);

        Certificate certificate = new Certificate();

        certificate.setSerial(serial);

        certificate.setLocalityName(subjectDto.getLocalityName());
        certificate.setStateOrProvinceName(subjectDto.getStateOrProvinceName());
        certificate.setCountryCode(subjectDto.getCountry());
        certificate.setCommonName(subjectDto.getCommonName());
        certificate.setOrganization(subjectDto.getOrganization());
        certificate.setOrganizationalUnit(subjectDto.getOrganizationalUnit());
        certificate.setEmailAddress(subjectDto.getEmailAddress());
        if (subjectDto.getSubjectAltNames() != null && !subjectDto.getSubjectAltNames().isEmpty()) {
            certificate.setSan(StringUtils.join(subjectDto.getSubjectAltNames(), ","));
        }

        certificate.setCertificate(CertificateUtils.write(x509Certificate));
        certificate.setPrivateKey(PrivateKeyUtils.write(key.getPrivate()));

        certificate.setValidFrom(validFrom.toDate());
        certificate.setValidUntil(validUntil.toDate());

        certificate.setStatus("Good");

        certificate.setIntermediate(intermediate);

        certificate.setUser(user);
        certificateRepository.save(certificate);

        String name = StringUtils.replace(certificate.getCommonName(), " ", "_");
        String caChain = name + "_ca-chain.crt";
        String fullChain = name + "_full-chain.crt";
        String changeit = "changeit";

        Root root = intermediate.getRoot();

        String rootName = StringUtils.replace("root-" + root.getCommonName(), " ", "_");

        ByteArrayOutputStream data = new ByteArrayOutputStream();
        ZipArchiveOutputStream zipArchiveOutputStream = new ZipArchiveOutputStream(data);

        {
            ZipArchiveEntry rootEntry = new ZipArchiveEntry(rootName + ".crt");
            rootEntry.setSize(root.getCertificate().getBytes(StandardCharsets.UTF_8).length);
            zipArchiveOutputStream.putArchiveEntry(rootEntry);
            zipArchiveOutputStream.write(root.getCertificate().getBytes(StandardCharsets.UTF_8));
            zipArchiveOutputStream.closeArchiveEntry();
        }

        {
            ZipArchiveEntry intermediateEntry = new ZipArchiveEntry(StringUtils.replace("intermediate-" + intermediate.getCommonName(), " ", "_") + ".crt");
            intermediateEntry.setSize(intermediate.getCertificate().getBytes(StandardCharsets.UTF_8).length);
            zipArchiveOutputStream.putArchiveEntry(intermediateEntry);
            zipArchiveOutputStream.write(intermediate.getCertificate().getBytes(StandardCharsets.UTF_8));
            zipArchiveOutputStream.closeArchiveEntry();
        }

        {
            String crt = intermediate.getCertificate() + root.getCertificate();
            ZipArchiveEntry caChainEntry = new ZipArchiveEntry(caChain);
            caChainEntry.setSize(crt.getBytes(StandardCharsets.UTF_8).length);
            zipArchiveOutputStream.putArchiveEntry(caChainEntry);
            zipArchiveOutputStream.write(crt.getBytes(StandardCharsets.UTF_8));
            zipArchiveOutputStream.closeArchiveEntry();
        }

        {
            String crt = certificate.getCertificate() + intermediate.getCertificate() + root.getCertificate();
            ZipArchiveEntry caChainEntry = new ZipArchiveEntry(fullChain);
            caChainEntry.setSize(crt.getBytes(StandardCharsets.UTF_8).length);
            zipArchiveOutputStream.putArchiveEntry(caChainEntry);
            zipArchiveOutputStream.write(crt.getBytes(StandardCharsets.UTF_8));
            zipArchiveOutputStream.closeArchiveEntry();
        }

        {
            StringBuffer buffer = new StringBuffer();
            buffer.append("# Reference OpenSSL command line to create p12/pfx file").append("\n");
            buffer.append("====================================================================================").append("\n");
            buffer.append("openssl pkcs12 -inkey " + name + ".pem -in " + fullChain + " -export -out " + name + ".p12 -passout pass:" + changeit).append("\n");
            buffer.append("openssl pkcs12 -inkey " + name + ".pem -in " + fullChain + " -export -out " + name + ".pfx -passout pass:" + changeit).append("\n");
            buffer.append("\n");
            buffer.append("# Installation Instructions for Apache").append("\n");
            buffer.append("====================================================================================").append("\n");
            buffer.append("SSLCertificateFile /your/path/to/" + name + ".crt").append("\n");
            buffer.append("SSLCertificateKeyFile /your/path/to/" + name + ".pem").append("\n");
            buffer.append("SSLCertificateChainFile /your/path/to/" + caChain).append("\n");
            buffer.append("\n");
            buffer.append("# Installation Instructions for SpringBoot").append("\n");
            buffer.append("====================================================================================").append("\n");
            buffer.append("server.ssl.enabled=true").append("\n");
            buffer.append("server.ssl.key-store=/your/path/to/" + name + ".p12").append("\n");
            buffer.append("server.ssl.key-store-type=PKCS12").append("\n");
            buffer.append("server.ssl.key-store-password=changeit").append("\n");
            buffer.append("\n");
            buffer.append("# Import/Delete JDK-11 cacert entry").append("\n");
            buffer.append("====================================================================================").append("\n");
            buffer.append("JAVA_HOME=/your/path/to/jdk11").append("\n");
            buffer.append("$JAVA_HOME/bin/keytool -delete -noprompt -alias " + rootName + " -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit").append("\n");
            buffer.append("$JAVA_HOME/bin/keytool -trustcacerts -keystore $JAVA_HOME/lib/security/cacerts -storepass " + changeit + " -alias " + rootName + " -import -file " + rootName + ".crt").append("\n");
            buffer.append("\n");
            buffer.append("# Import/Delete JDK-8 cacert entry").append("\n");
            buffer.append("====================================================================================").append("\n");
            buffer.append("JAVA_HOME=/your/path/to/jdk8").append("\n");
            buffer.append("$JAVA_HOME/bin/keytool -delete -noprompt -alias " + rootName + " -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass changeit").append("\n");
            buffer.append("$JAVA_HOME/bin/keytool -trustcacerts -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass " + changeit + " -alias " + rootName + " -import -file " + rootName + ".crt").append("\n");
            buffer.append("\n");
            buffer.append("# Create Trust Store P12 File").append("\n");
            buffer.append("====================================================================================").append("\n");
            buffer.append("openssl pkcs12 -nokeys -in " + rootName + ".crt -export -out " + rootName + ".p12 -passout pass:" + changeit).append("\n");

            String crt = buffer.toString();
            ZipArchiveEntry caChainEntry = new ZipArchiveEntry("README.txt");
            caChainEntry.setSize(crt.getBytes(StandardCharsets.UTF_8).length);
            zipArchiveOutputStream.putArchiveEntry(caChainEntry);
            zipArchiveOutputStream.write(crt.getBytes(StandardCharsets.UTF_8));
            zipArchiveOutputStream.closeArchiveEntry();
        }

        {
            ZipArchiveEntry certificateEntry = new ZipArchiveEntry(name + ".crt");
            certificateEntry.setSize(certificate.getCertificate().getBytes(StandardCharsets.UTF_8).length);
            zipArchiveOutputStream.putArchiveEntry(certificateEntry);
            zipArchiveOutputStream.write(certificate.getCertificate().getBytes(StandardCharsets.UTF_8));
            zipArchiveOutputStream.closeArchiveEntry();
        }

        {
            ZipArchiveEntry privateKeyEntry = new ZipArchiveEntry(name + ".pem");
            privateKeyEntry.setSize(certificate.getPrivateKey().getBytes(StandardCharsets.UTF_8).length);
            zipArchiveOutputStream.putArchiveEntry(privateKeyEntry);
            zipArchiveOutputStream.write(certificate.getPrivateKey().getBytes(StandardCharsets.UTF_8));
            zipArchiveOutputStream.closeArchiveEntry();
        }

        zipArchiveOutputStream.close();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "inline; filename=\"" + certificate.getId() + ".zip\"");
        return ResponseEntity.ok().headers(headers).body(data.toByteArray());
    }

}
