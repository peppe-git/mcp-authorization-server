-- SPDX-License-Identifier: Apache-2.0
--
-- Schema of the JDBC stores of mcp-authorization-server (PostgreSQL; tested with PostgreSQL 17).
-- Tokens, codes and refresh tokens are stored only as lower-case hex SHA-256 hashes.
-- Apply it with your migration tool; the starter never runs DDL by itself.

CREATE TABLE mcp_oauth_client (
    client_id       VARCHAR(255)             NOT NULL PRIMARY KEY,
    client_name     VARCHAR(255)             NOT NULL,
    redirect_uris   TEXT                     NOT NULL, -- newline-separated
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE mcp_oauth_authorization_request (
    request_id          VARCHAR(64)              NOT NULL PRIMARY KEY,
    client_id           VARCHAR(2048)            NOT NULL,
    client_name         VARCHAR(255)             NOT NULL,
    client_verification VARCHAR(16)              NOT NULL,
    verified_domain     VARCHAR(255),
    redirect_uri        VARCHAR(2048)            NOT NULL,
    code_challenge      VARCHAR(64)              NOT NULL,
    scopes              VARCHAR(2000)            NOT NULL, -- space-separated
    state               VARCHAR(1024),
    resource            VARCHAR(2048)            NOT NULL,
    expires_at          TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX mcp_oauth_authorization_request_expires_idx ON mcp_oauth_authorization_request (expires_at);

CREATE TABLE mcp_oauth_authorization_code (
    code_hash       CHAR(64)                 NOT NULL PRIMARY KEY,
    client_id       VARCHAR(2048)            NOT NULL,
    client_name     VARCHAR(255)             NOT NULL,
    redirect_uri    VARCHAR(2048)            NOT NULL,
    code_challenge  VARCHAR(64)              NOT NULL,
    scopes          VARCHAR(2000)            NOT NULL,
    resource        VARCHAR(2048)            NOT NULL,
    subject         VARCHAR(255)             NOT NULL,
    expires_at      TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX mcp_oauth_authorization_code_expires_idx ON mcp_oauth_authorization_code (expires_at);

CREATE TABLE mcp_oauth_grant (
    grant_id        VARCHAR(64)              NOT NULL PRIMARY KEY,
    subject         VARCHAR(255)             NOT NULL,
    client_id       VARCHAR(2048)            NOT NULL,
    client_name     VARCHAR(255)             NOT NULL,
    scopes          VARCHAR(2000)            NOT NULL,
    resource        VARCHAR(2048)            NOT NULL,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    last_used_at    TIMESTAMP WITH TIME ZONE,
    revoked_at      TIMESTAMP WITH TIME ZONE,
    revoked_reason  VARCHAR(32)
);
CREATE INDEX mcp_oauth_grant_subject_idx ON mcp_oauth_grant (subject);

CREATE TABLE mcp_oauth_token (
    token_id            VARCHAR(64)              NOT NULL PRIMARY KEY,
    grant_id            VARCHAR(64)              NOT NULL REFERENCES mcp_oauth_grant (grant_id) ON DELETE CASCADE,
    access_hash         CHAR(64)                 NOT NULL UNIQUE,
    refresh_hash        CHAR(64)                 NOT NULL UNIQUE,
    status              VARCHAR(16)              NOT NULL, -- ACTIVE, ROTATED, SUPERSEDED
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    access_expires_at   TIMESTAMP WITH TIME ZONE NOT NULL,
    refresh_expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    ended_at            TIMESTAMP WITH TIME ZONE,
    first_used_at       TIMESTAMP WITH TIME ZONE
);
CREATE INDEX mcp_oauth_token_grant_idx ON mcp_oauth_token (grant_id);
CREATE INDEX mcp_oauth_token_refresh_expires_idx ON mcp_oauth_token (refresh_expires_at);
