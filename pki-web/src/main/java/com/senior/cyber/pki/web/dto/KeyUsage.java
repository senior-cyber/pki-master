package com.senior.cyber.pki.web.dto;

public enum KeyUsage {

    digitalSignature,
    nonRepudiation,
    keyEncipherment,
    dataEncipherment,
    keyAgreement,
    keyCertSign,
    cRLSign,
    encipherOnly,
    decipherOnly;

}
