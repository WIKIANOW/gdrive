PRAGMA defer_foreign_keys=TRUE;
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    name TEXT,
    client_id TEXT,
    client_secret TEXT,
    refresh_token TEXT,
    folder_id TEXT, 
    used_space INTEGER DEFAULT 0,
    total_space INTEGER DEFAULT 16106127360 
, status TEXT DEFAULT 'active');

CREATE TABLE users (
    username TEXT PRIMARY KEY,
    password TEXT,
    role TEXT DEFAULT 'user', 
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
, max_space INTEGER DEFAULT 5368709120);

CREATE TABLE user_permissions (
    username TEXT,
    account_id TEXT,
    PRIMARY KEY (username, account_id),
    FOREIGN KEY (username) REFERENCES users(username),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);
CREATE TABLE files (
    file_id TEXT PRIMARY KEY, 
    name TEXT, 
    size INTEGER, 
    drive_file_id TEXT, 
    account_id TEXT, 
    owner TEXT, 
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
, status TEXT DEFAULT 'private');
