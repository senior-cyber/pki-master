CREATE TABLE tbl_rbac_role
(
    role_id     VARCHAR(36)  NOT NULL,
    name        VARCHAR(100) NOT NULL,
    description VARCHAR(200) NOT NULL,
    enabled     TINYINT(1) NOT NULL DEFAULT 1,
    UNIQUE KEY (name),
    PRIMARY KEY (role_id)
);

CREATE TABLE tbl_rbac_group
(
    group_id    VARCHAR(36)  NOT NULL,
    name        VARCHAR(100) NOT NULL,
    description VARCHAR(200) NOT NULL,
    enabled     TINYINT(1) NOT NULL DEFAULT 1,
    UNIQUE KEY (name),
    PRIMARY KEY (group_id)
);

CREATE TABLE tbl_rbac_user
(
    user_id       VARCHAR(36)  NOT NULL,
    enabled       TINYINT(1)   NOT NULL DEFAULT 1,
    display_name  VARCHAR(200) NOT NULL,
    login         VARCHAR(200) NOT NULL,
    pwd           VARCHAR(200) NOT NULL,
    email_address VARCHAR(200) NOT NULL,
    last_seen     DATETIME     NOT NULL,
    UNIQUE KEY (login),
    UNIQUE KEY (email_address),
    INDEX         idx_display_name (display_name),
    PRIMARY KEY (user_id)
);

CREATE TABLE tbl_rbac_user_role
(
    user_role_id VARCHAR(36) NOT NULL,
    user_id      VARCHAR(36) NOT NULL,
    role_id      VARCHAR(36) NOT NULL,
    UNIQUE KEY (user_id, role_id),
    PRIMARY KEY (user_role_id)
);

CREATE TABLE tbl_rbac_user_group
(
    user_group_id VARCHAR(36) NOT NULL,
    user_id       VARCHAR(36) NOT NULL,
    group_id      VARCHAR(36) NOT NULL,
    UNIQUE KEY (user_id, group_id),
    PRIMARY KEY (user_group_id)
);

CREATE TABLE tbl_rbac_group_role
(
    group_role_id VARCHAR(36) NOT NULL,
    role_id       VARCHAR(36) NOT NULL,
    group_id      VARCHAR(36) NOT NULL,
    UNIQUE KEY (role_id, group_id),
    PRIMARY KEY (group_role_id)
);

CREATE TABLE tbl_rbac_deny_role
(
    deny_role_id VARCHAR(36) NOT NULL,
    role_id      VARCHAR(36) NOT NULL,
    user_id      VARCHAR(36) NOT NULL,
    UNIQUE KEY (role_id, user_id),
    PRIMARY KEY (deny_role_id)
);