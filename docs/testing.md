# Testing nimbra-core

```sh
cargo test --workspace
```

runs every unit test. They use sample data and `example.com` addresses, and never touch the network, a real
mailbox or the Keychain (the FFI tests use an in-memory one and a temporary folder).

## Live tests

The IMAP and SMTP code (`imap_mail.rs`, `smtp.rs`, `mime.rs`) also has live tests that talk to real servers on your
Mac: Dovecot for IMAP and Mailpit for SMTP, in containers (OrbStack or Docker). They're marked `#[ignore]`, so
`cargo test` skips them. Run them when you change that code.

Set them up once, in a folder of your own outside the repository (for example `~/nimbra-mailtest`).

**1. Certificates.** A test CA, and a `localhost` certificate signed by it:

```sh
mkdir -p certs && cd certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 3650 -subj "/CN=Nimbra test CA"
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 3650 -extfile ext.cnf
cd ..
```

**2. `dovecot.conf`**, next to `certs/`:

```
protocols = imap
listen = *
log_path = /dev/stderr
ssl = required
ssl_cert = </certs/server.pem
ssl_key = </certs/server.key
disable_plaintext_auth = yes
auth_mechanisms = plain login
first_valid_uid = 1000
passdb {
  driver = static
  args = password=pass
}
userdb {
  driver = static
  args = uid=1000 gid=1000 home=/srv/mail/%u
}
mail_location = maildir:~/Maildir
namespace inbox {
  inbox = yes
  separator = /
  mailbox Drafts {
    special_use = \Drafts
    auto = subscribe
  }
  mailbox Sent {
    special_use = \Sent
    auto = subscribe
  }
  mailbox Trash {
    special_use = \Trash
    auto = subscribe
  }
  mailbox Junk {
    special_use = \Junk
    auto = subscribe
  }
  mailbox Archive {
    special_use = \Archive
    auto = subscribe
  }
}
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}
```

Any user name works, with the password `pass`, and every mailbox has Drafts, Sent, Trash, Junk and Archive.

**3. The servers**, from that folder:

```sh
docker run -d --name nimbra-dovecot -p 127.0.0.1:10993:993 \
  -v "$PWD/dovecot.conf:/etc/dovecot/dovecot.conf:ro" -v "$PWD/certs:/certs:ro" alpine:3.20 \
  sh -c 'apk add --no-cache dovecot && adduser -D -u 1000 vmail && mkdir -p /srv/mail && chown 1000:1000 /srv/mail && exec dovecot -F'

docker run -d --name nimbra-mailpit -p 127.0.0.1:10587:1025 -v "$PWD/certs:/certs:ro" axllent/mailpit \
  --smtp-tls-cert /certs/server.pem --smtp-tls-key /certs/server.key --smtp-auth-accept-any --smtp-require-starttls
```

**4. Run them**, from this repository, pointing at your test CA (only debug builds read `NIMBRA_TEST_CA`):

```sh
NIMBRA_TEST_CA=~/nimbra-mailtest/certs/ca.pem cargo test live -- --ignored --test-threads=1
```

Each test makes its own mail user, so they can run again without cleaning up. When you're done:

```sh
docker rm -f nimbra-dovecot nimbra-mailpit
```

The IDLE test can take over 10 seconds on a server that has only just started; run it again if it times out once.
