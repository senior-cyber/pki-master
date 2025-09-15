//package com.senior.cyber.pki.dao.entity.pki;
//
//import jakarta.persistence.*;
//import lombok.AccessLevel;
//import lombok.Getter;
//import lombok.Setter;
//import org.hibernate.annotations.UuidGenerator;
//
//import java.io.Serializable;
//
//@Getter
//@Setter
//@Entity
//@Table(name = "tbl_queue")
//public class Queue implements Serializable {
//
//    @Id
//    @UuidGenerator
//    @Column(name = "queue_id")
//    @Setter(AccessLevel.NONE)
//    private String id;
//
//    @ManyToOne(fetch = FetchType.LAZY)
//    @JoinColumn(name = "key_id", referencedColumnName = "key_id")
//    private Key key;
//
//}
