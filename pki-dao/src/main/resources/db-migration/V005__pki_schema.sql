CREATE TABLE tbl_iban
(
    iban_id       VARCHAR(36)  NOT NULL,
    country       VARCHAR(200) NOT NULL,
    alpha2_code   VARCHAR(2)   NOT NULL,
    alpha3_code   VARCHAR(3)   NOT NULL,
    alpha_numeric VARCHAR(3)   NOT NULL,
    UNIQUE KEY (country),
    UNIQUE KEY (alpha2_code),
    UNIQUE KEY (alpha3_code),
    UNIQUE KEY (alpha_numeric),
    PRIMARY KEY (iban_id)
);

CREATE TABLE tbl_key
(
    key_id           VARCHAR(36) NOT NULL,
    serial           BIGINT      NOT NULL,
    user_id          VARCHAR(36) NOT NULL,
    private_key_pem  TEXT        NULL,
    public_key_pem   TEXT        NOT NULL,
    type             VARCHAR(30) NOT NULL,
    created_datetime DATETIME    NOT NULL,
    INDEX (created_datetime),
    INDEX (user_id),
    UNIQUE KEY (serial),
    PRIMARY KEY (key_id)
);

CREATE TABLE tbl_certificate
(
    certificate_id         VARCHAR(36)  NOT NULL,
    serial                 BIGINT       NOT NULL,
    common_name            VARCHAR(200) NULL,
    organization           VARCHAR(200) NULL,
    organizational_unit    VARCHAR(200) NULL,
    country_code           VARCHAR(2)   NULL,
    locality_name          VARCHAR(200) NULL,
    state_or_province_name VARCHAR(200) NULL,
    email_address          VARCHAR(200) NULL,
    key_id                 VARCHAR(36)  NOT NULL,
    certificate_pem        TEXT         NOT NULL,
    san                    TEXT         NULL,
    revoked_date           DATE         NULL,
    revoked_reason         VARCHAR(30)  NULL,
    valid_from             DATE         NOT NULL,
    valid_until            DATE         NOT NULL,
    created_datetime       DATETIME     NOT NULL,
    status                 VARCHAR(10)  NOT NULL,
    type                   VARCHAR(20)  NOT NULL,
    user_id                VARCHAR(36)  NOT NULL,
    issuer_certificate_id  VARCHAR(36)  NULL,
    crl_certificate_id     VARCHAR(36)  NULL,
    ocsp_certificate_id    VARCHAR(36)  NULL,

    INDEX (created_datetime),
    INDEX (user_id),
    UNIQUE KEY (serial),
    PRIMARY KEY (certificate_id)
);