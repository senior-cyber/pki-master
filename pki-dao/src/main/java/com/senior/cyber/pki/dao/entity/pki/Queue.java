package com.senior.cyber.pki.dao.entity.pki;

import com.senior.cyber.pki.common.dto.CertificateTypeEnum;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;
import java.util.Date;

@Getter
@Setter
@Entity
@Table(name = "tbl_queue")
public class Queue implements Serializable {

    @Id
    @UuidGenerator
    @Column(name = "queue_id")
    @Setter(AccessLevel.NONE)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_certificate_id", referencedColumnName = "certificate_id")
    private Certificate issuerCertificate;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_key_id", referencedColumnName = "key_id")
    private Key issuerKey;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "key_id", referencedColumnName = "key_id")
    private Key key;

    @Column(name = "subject")
    private String subject;

    @Column(name = "type")
    @Enumerated(EnumType.STRING)
    private CertificateTypeEnum type;

    @Column(name = "priority")
    @Temporal(TemporalType.TIMESTAMP)
    private Date priority;

}
