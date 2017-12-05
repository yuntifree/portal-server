use portal;

CREATE TABLE IF NOT EXISTS users
(
    uid     bigint unsigned NOT NULL AUTO_INCREMENT,
    username    varchar(36) NOT NULL,
    phone       varchar(16) NOT NULL,
    ctime   datetime NOT NULL DEFAULT '2017-12-01',
    PRIMARY KEY(uid),
    UNIQUE KEY(username),
    KEY(phone),
    KEY(ctime)
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS phone_code
(
    id  bigint unsigned NOT NULL AUTO_INCREMENT,
    phone   varchar(16) NOT NULL,
    code    int unsigned NOT NULL DEFAULT 0,
    used    tinyint unsigned NOT NULL DEFAULT 0,
    ctime   datetime NOT NULL DEFAULT '2017-12-01',
    stime   datetime NOT NULL DEFAULT '2017-12-01',
    etime   datetime NOT NULL DEFAULT '2017-12-01',
    PRIMARY KEY(id),
    KEY(phone),
    KEY(ctime)
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS user_mac
(
    id      bigint unsigned NOT NULL AUTO_INCREMENT,
    phone   varchar(16) NOT NULL,
    mac     varchar(36) NOT NULL DEFAULT '',
    ctime   datetime NOT NULL DEFAULT '2017-12-01',
    PRIMARY KEY(id),
    UNIQUE KEY(mac),
    KEY(phone)
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS online_record
(
    id      bigint unsigned NOT NULL AUTO_INCREMENT,
    phone   varchar(16) NOT NULL,
    acname  varchar(32) NOT NULL DEFAULT '',
    acip    varchar(32) NOT NULL DEFAULT '',
    userip  varchar(32) NOT NULL DEFAULT '',
    usermac varchar(32) NOT NULL DEFAULT '',
    apmac   varchar(32) NOT NULL DEFAULT '',
    ctime   datetime NOT NULL DEFAULT '2017-11-01',
    PRIMARY KEY(id),
    KEY(phone),
    KEY(ctime)
) ENGINE = InnoDB;


