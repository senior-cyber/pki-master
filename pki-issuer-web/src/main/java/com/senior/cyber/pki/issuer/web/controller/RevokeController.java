package com.senior.cyber.pki.issuer.web.controller;

import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.Intermediate;
import com.senior.cyber.pki.dao.entity.Root;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.IntermediateStatusEnum;
import com.senior.cyber.pki.dao.enums.RootStatusEnum;
import com.senior.cyber.pki.issuer.web.repository.CertificateRepository;
import com.senior.cyber.pki.issuer.web.repository.IntermediateRepository;
import com.senior.cyber.pki.issuer.web.repository.RootRepository;
import com.senior.cyber.pki.issuer.web.repository.UserRepository;
import com.senior.cyber.pki.issuer.web.utility.UserUtility;
import org.joda.time.LocalDate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping(path = "/revoke")
public class RevokeController {

    @Autowired
    protected RootRepository rootRepository;

    @Autowired
    protected UserRepository userRepository;

    @Autowired
    protected IntermediateRepository intermediateRepository;

    @Autowired
    protected CertificateRepository certificateRepository;

    @RequestMapping(path = "/root/{id}", method = RequestMethod.DELETE)
    public ResponseEntity<Void> root(@PathVariable("id") String id,
                                     HttpServletRequest request) {
        User user = UserUtility.authenticate(request);

        Optional<Root> optionalRoot = rootRepository.findByIdAndUser(id, user);
        Root root = optionalRoot.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, id + " is not found"));

        Date now = LocalDate.now().toDate();

        root.setRevokedDate(now);
        root.setStatus(RootStatusEnum.Revoked);
        rootRepository.save(root);

        List<Intermediate> intermediates = intermediateRepository.findByRootAndStatus(root, IntermediateStatusEnum.Good);
        for (Intermediate intermediate : intermediates) {
            intermediate.setRevokedDate(now);
            intermediate.setRevokedReason("issuer was revoked");
            intermediate.setStatus(IntermediateStatusEnum.Revoked);
            intermediateRepository.save(intermediate);
            List<Certificate> certificates = certificateRepository.findByIntermediateAndStatus(intermediate, CertificateStatusEnum.Good);
            for (Certificate certificate : certificates) {
                certificate.setRevokedDate(now);
                certificate.setRevokedReason("issuer was revoked");
                certificate.setStatus(CertificateStatusEnum.Revoked);
                certificateRepository.save(certificate);
            }
        }
        return ResponseEntity.ok(null);
    }

    @RequestMapping(path = "/intermediate/{id}", method = RequestMethod.DELETE)
    public ResponseEntity<Void> intermediate(@PathVariable("id") String id,
                                             HttpServletRequest request) {
        User user = UserUtility.authenticate(request);

        Optional<Intermediate> optionalIntermediate = intermediateRepository.findByIdAndUser(id, user);
        Intermediate intermediate = optionalIntermediate.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, id + " is not found"));

        Date now = LocalDate.now().toDate();

        intermediate.setRevokedDate(now);
        intermediate.setRevokedReason("Unknown");
        intermediate.setStatus(IntermediateStatusEnum.Revoked);
        intermediateRepository.save(intermediate);

        List<Certificate> certificates = certificateRepository.findByIntermediateAndStatus(intermediate, CertificateStatusEnum.Good);
        for (Certificate certificate : certificates) {
            certificate.setRevokedDate(now);
            certificate.setRevokedReason("issuer was revoked");
            certificate.setStatus(CertificateStatusEnum.Revoked);
            certificateRepository.save(certificate);
        }

        return ResponseEntity.ok(null);
    }

    @RequestMapping(path = "/certificate/{id}", method = RequestMethod.DELETE)
    public ResponseEntity<Void> certificate(@PathVariable("id") String id,
                                            HttpServletRequest request) {
        User user = UserUtility.authenticate(request);

        Optional<Certificate> optionalCertificate = certificateRepository.findByIdAndUser(id, user);
        Certificate certificate = optionalCertificate.orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, id + " is not found"));

        Date now = LocalDate.now().toDate();

        certificate.setRevokedDate(now);
        certificate.setRevokedReason("Unknown");

        certificate.setStatus(CertificateStatusEnum.Revoked);

        certificateRepository.save(certificate);
        return ResponseEntity.ok(null);
    }

}
