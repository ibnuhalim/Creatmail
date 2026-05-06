CREATE TABLE IF NOT EXISTS mailboxes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS emails (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mailbox_email TEXT NOT NULL,
  from_addr TEXT,
  to_addr TEXT,
  subject TEXT,
  raw TEXT,
  preview TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mailboxes_email ON mailboxes(email);
CREATE INDEX IF NOT EXISTS idx_mailboxes_expires ON mailboxes(expires_at);
CREATE INDEX IF NOT EXISTS idx_emails_mailbox ON emails(mailbox_email);
CREATE INDEX IF NOT EXISTS idx_emails_expires ON emails(expires_at);
