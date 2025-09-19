package com.senior.cyber.pki.api.queue.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.senior.cyber.pki.common.dto.*;
import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.entity.pki.Queue;
import com.senior.cyber.pki.dao.repository.pki.CertificateRepository;
import com.senior.cyber.pki.dao.repository.pki.KeyRepository;
import com.senior.cyber.pki.dao.repository.pki.QueueRepository;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Slf4j
@RestController
public class QueueController {

    private static final Logger LOGGER = LoggerFactory.getLogger(QueueController.class);

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected KeyRepository keyRepository;

    @Autowired
    protected QueueRepository queueRepository;

    @Autowired
    protected ObjectMapper objectMapper;

    @RequestMapping(path = "/queue/request", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<QueueRequestResponse> queueRequest(RequestEntity<QueueRequestRequest> httpRequest) throws JsonProcessingException {
        QueueRequestRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        log.debug("QueueRequestRequest [{}]", this.objectMapper.writeValueAsString(request));

        switch (request.getType()) {
            case CRL, OCSP -> {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
            case ROOT_CA -> {
                Queue queue = new Queue();
                Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST));
                queue.setKey(key);
                queue.setIssuerKey(key);
                queue.setSubject(objectMapper.writeValueAsString(request.getSubject()));
                queue.setType(request.getType());
                queue.setPriority(new Date());
                this.queueRepository.save(queue);
                QueueRequestResponse response = QueueRequestResponse.builder().build();
                response.setQueueId(queue.getId());
                log.debug("QueueRequestResponse [{}]", this.objectMapper.writeValueAsString(response));
                return ResponseEntity.ok(response);
            }
            case SUBORDINATE_CA, ISSUING_CA, TLS_SERVER, mTLS_SERVER, mTLS_CLIENT -> {
                Queue queue = new Queue();
                Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST));
                queue.setKey(key);
                Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerCertificateId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST));
                queue.setIssuerCertificate(issuerCertificate);
                Key issuerKey = this.keyRepository.findById(issuerCertificate.getKey().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST));
                queue.setIssuerKey(issuerKey);
                queue.setSubject(objectMapper.writeValueAsString(request.getSubject()));
                queue.setType(request.getType());
                queue.setPriority(new Date());
                this.queueRepository.save(queue);
                QueueRequestResponse response = QueueRequestResponse.builder().build();
                response.setQueueId(queue.getId());
                log.debug("QueueRequestResponse [{}]", this.objectMapper.writeValueAsString(response));
                return ResponseEntity.ok(response);
            }
            default -> {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
        }
    }

    @RequestMapping(path = "/queue/{id}", method = RequestMethod.GET, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<QueueResponse> queue(@PathVariable("id") String id) throws JsonProcessingException {
        Queue _queue = this.queueRepository.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST));

        QueueResponse response = QueueResponse.create();
        response.setId(_queue.getId());
        response.setSubject(this.objectMapper.readValue(_queue.getSubject(), Subject.class));
        if (_queue.getIssuerCertificate() != null) {
            Certificate issuerCertificate = this.certificateRepository.findById(_queue.getIssuerCertificate().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST));
            response.setIssuerCertificate(issuerCertificate.getCertificate());
        }
        response.setType(_queue.getType());
        response.setKeyId(_queue.getKey().getId());

        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/queue/search", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<QueueSearchResponse> queueSearch(RequestEntity<QueueSearchRequest> httpRequest) throws OperatorCreationException, JsonProcessingException {
        QueueSearchRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        log.debug("QueueSearchRequest [{}]", this.objectMapper.writeValueAsString(request));

        Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST));
        List<Queue> _queues = this.queueRepository.findByIssuerKey(key);
        List<com.senior.cyber.pki.common.dto.Queue> queues = new ArrayList<>();
        for (Queue _queue : _queues) {
            com.senior.cyber.pki.common.dto.Queue queue = com.senior.cyber.pki.common.dto.Queue.create();
            queue.setId(_queue.getId());
            queue.setSubject(this.objectMapper.readValue(_queue.getSubject(), Subject.class));
            if (_queue.getIssuerCertificate() != null) {
                Certificate issuerCertificate = this.certificateRepository.findById(_queue.getIssuerCertificate().getId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST));
                queue.setIssuerCertificate(issuerCertificate.getCertificate());
            }
            queue.setType(_queue.getType());
            queue.setKeyId(_queue.getKey().getId());
            queues.add(queue);
        }
        QueueSearchResponse response = QueueSearchResponse.create();
        response.setQueues(queues);
        log.debug("QueueSearchResponse [{}]", this.objectMapper.writeValueAsString(response));
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/queue/approve", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<QueueApproveResponse> queueApprove(RequestEntity<QueueApproveRequest> httpRequest) throws OperatorCreationException {
        QueueApproveRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        QueueApproveResponse response = QueueApproveResponse.create();
        return ResponseEntity.ok(response);
    }

}
