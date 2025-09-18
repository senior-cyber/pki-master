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
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

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
    protected ObjectMapper mapper;

    @RequestMapping(path = "/queue/request", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<QueueRequestResponse> queueRequest(RequestEntity<QueueRequestRequest> httpRequest) throws JsonProcessingException {
        QueueRequestRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Certificate issuerCertificate = this.certificateRepository.findById(request.getIssuerCertificateId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST));
        Key issuerKey = this.keyRepository.findById(request.getIssuerKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST));
        Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST));

        Queue queue = new Queue();
        queue.setIssuerCertificate(issuerCertificate);
        queue.setIssuerKey(issuerKey);
        queue.setKey(key);
        queue.setSubject(mapper.writeValueAsString(request.getSubject()));
        queue.setType(request.getType());
        queue.setPriority(new Date());
        this.queueRepository.save(queue);

        QueueRequestResponse response = QueueRequestResponse.builder().build();
        response.setQueueId(queue.getId());
        return ResponseEntity.ok(response);
    }

    @RequestMapping(path = "/queue/search", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<QueueSearchResponse> queueSearch(RequestEntity<QueueSearchRequest> httpRequest) throws OperatorCreationException, JsonProcessingException {
        QueueSearchRequest request = httpRequest.getBody();
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        Key key = this.keyRepository.findById(request.getKeyId()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST));
        List<Queue> _queues = this.queueRepository.findByIssuerKey(key);
        List<com.senior.cyber.pki.common.dto.Queue> queues = new ArrayList<>();
        for (Queue _queue : _queues) {
            com.senior.cyber.pki.common.dto.Queue queue = com.senior.cyber.pki.common.dto.Queue.create();
            queue.setId(_queue.getId());
            queue.setSubject(this.mapper.readValue(_queue.getSubject(), Subject.class));
            queue.setIssuerCertificate(_queue.getIssuerCertificate().getCertificate());
            queue.setType(_queue.getType());
            queue.setKeyId(_queue.getKey().getId());
            queues.add(queue);
        }
        QueueSearchResponse response = QueueSearchResponse.create();
        response.setQueues(queues);
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
