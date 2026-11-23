//! Sending mail over SMTP, for accounts that are not Gmail: one already-built message to its
//! recipients, through the account's own server, signed in with its password (or, for a
//! Microsoft account, an OAuth access token: AUTH XOAUTH2).
//!
//! Security notes:
//! - The connection is TLS from the first byte (`Tls`), or made secure with STARTTLS
//!   before anything else is said (`StartTls`). A server that does not offer STARTTLS is
//!   refused, never spoken to in plain text, and the password (or token) is only ever
//!   sent over TLS.
//! - The password and the token are never written to a log or put in an error.
//! - Every address is checked before it goes into a command, so none can carry a line break
//!   or a second command with it.
//! - The plain connection is read one byte at a time until STARTTLS is answered, so nothing
//!   sent after the answer (the start of TLS) is read as plain text.
//! - The name given in EHLO is a fixed one, never the Mac's own name.
//! - What the server says is cut short and stripped of control characters before it is
//!   shown.

use std::io::{self, Read, Write};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::mail::{self, MayHaveArrived, Offline};
use crate::servers::{Secret, Security, Server};
use crate::tls;

/// What this end calls itself in EHLO: the same for everyone, so it says nothing about the
/// Mac or its network.
const HELLO_NAME: &str = "[127.0.0.1]";
/// The longest line a server may answer with (RFC 5321 asks for at most 512).
const MAX_LINE: usize = 2048;
/// The most lines one answer may have.
const MAX_LINES: usize = 100;
/// How much of what a server says is kept for an error.
const MAX_TEXT: usize = 200;

/// The server did not accept the user name or password.
#[derive(Debug)]
pub struct AuthFailed;

impl std::fmt::Display for AuthFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The server did not accept the user name or password.")
    }
}

impl std::error::Error for AuthFailed {}

/// Sends one message, already built (RFC 5322), to `recipients`.
pub fn send(
    server: &Server,
    username: &str,
    secret: &Secret,
    from: &str,
    recipients: &[String],
    message: &[u8],
) -> Result<()> {
    check_envelope(from, recipients)?;
    let (mut session, extensions) = open(server, username, secret)?;
    deliver(&mut session, &extensions, from, recipients, message)?;
    session.quit();
    Ok(())
}

/// Connects, makes the connection secure and signs in: whether the server and password
/// work, for setting up an account.
pub fn check_login(server: &Server, username: &str, secret: &Secret) -> Result<()> {
    let (mut session, _) = open(server, username, secret)?;
    session.quit();
    Ok(())
}

/// A secure, signed-in connection. Failing to connect at all keeps the error from `tls`
/// (`Offline`, or a certificate that does not check out).
fn open(
    server: &Server,
    username: &str,
    secret: &Secret,
) -> Result<(Session<tls::TlsStream>, Extensions)> {
    server.check()?;
    let mut session = match server.security {
        Security::Tls => {
            let mut session = Session::new(tls::connect(&server.host, server.port)?);
            session.greeting().map_err(mail::before_sending)?;
            session
        }
        Security::StartTls => {
            let mut plain = Session::new(tls::tcp(&server.host, server.port)?);
            start_tls(&mut plain).map_err(mail::before_sending)?;
            Session::new(tls::upgrade(plain.stream, &server.host)?)
        }
    };
    let extensions = signed_in(&mut session, username, secret).map_err(mail::before_sending)?;
    Ok((session, extensions))
}

/// On a plain connection: the greeting, EHLO and STARTTLS, read so that nothing past the
/// server's 220 is taken from the connection.
fn start_tls<S: Read + Write>(session: &mut Session<S>) -> Result<()> {
    session.greeting()?;
    let extensions = session.ehlo()?;
    if !extensions.starttls {
        bail!(
            "The mail server does not offer a secure connection (STARTTLS), so Nimbra did not use it."
        );
    }
    session.expect("STARTTLS", 220, "starting a secure connection")?;
    Ok(())
}

/// Once the connection is secure: EHLO (again, after STARTTLS) and AUTH.
fn signed_in<S: Read + Write>(
    session: &mut Session<S>,
    username: &str,
    secret: &Secret,
) -> Result<Extensions> {
    let extensions = session.ehlo()?;
    sign_in(session, &extensions, username, secret)?;
    Ok(extensions)
}

fn sign_in<S: Read + Write>(
    session: &mut Session<S>,
    extensions: &Extensions,
    username: &str,
    secret: &Secret,
) -> Result<()> {
    let refused = |reply: &Reply| -> anyhow::Error {
        if matches!(reply.code, 535 | 534) {
            AuthFailed.into()
        } else {
            reply.error("signing in")
        }
    };
    let password = match secret {
        Secret::Password(password) => password,
        Secret::Bearer(token) => {
            if !extensions.offers_auth("XOAUTH2") {
                bail!("The mail server does not offer a way to sign in that Nimbra knows.");
            }
            let initial = STANDARD.encode(crate::servers::xoauth2(username, token)?);
            let mut reply = session.command(&format!("AUTH XOAUTH2 {initial}"))?;
            // A refused token comes back as a challenge (base64 JSON), answered with an
            // empty line; then the server says no.
            if reply.code == 334 {
                reply = session.command("")?;
            }
            if reply.code != 235 {
                return Err(refused(&reply));
            }
            return Ok(());
        }
    };
    if username.is_empty() || username.contains('\0') || password.contains('\0') {
        bail!("The user name or password is not valid.");
    }
    if extensions.offers_auth("PLAIN") {
        let token = STANDARD.encode(format!("\0{username}\0{password}"));
        let reply = session.command(&format!("AUTH PLAIN {token}"))?;
        if reply.code != 235 {
            return Err(refused(&reply));
        }
    } else if extensions.offers_auth("LOGIN") {
        for (line, code) in [
            ("AUTH LOGIN".to_string(), 334),
            (STANDARD.encode(username), 334),
            (STANDARD.encode(password), 235),
        ] {
            let reply = session.command(&line)?;
            if reply.code != code {
                return Err(refused(&reply));
            }
        }
    } else {
        bail!("The mail server does not offer a way to sign in that Nimbra knows.");
    }
    Ok(())
}

/// MAIL, RCPT and DATA. Anything that fails before the message's final dot is sent means
/// it was not sent; a connection lost after it, before the server answered, means it may
/// have been.
fn deliver<S: Read + Write>(
    session: &mut Session<S>,
    extensions: &Extensions,
    from: &str,
    recipients: &[String],
    message: &[u8],
) -> Result<()> {
    envelope(session, extensions, from, recipients, message).map_err(mail::before_sending)?;
    let answer = session
        .write_raw(b".\r\n")
        .and_then(|()| session.reply())
        .context(MayHaveArrived)?;
    if !answer.is_ok() {
        return Err(answer.error("sending the message"));
    }
    Ok(())
}

/// Everything up to the message's final dot.
fn envelope<S: Read + Write>(
    session: &mut Session<S>,
    extensions: &Extensions,
    from: &str,
    recipients: &[String],
    message: &[u8],
) -> Result<()> {
    check_envelope(from, recipients)?;
    let body = if extensions.eight_bit && !message.is_ascii() {
        " BODY=8BITMIME"
    } else {
        ""
    };
    session.expect(
        &format!("MAIL FROM:<{from}>{body}"),
        250,
        "giving the sender",
    )?;
    for recipient in recipients {
        let reply = session.command(&format!("RCPT TO:<{recipient}>"))?;
        if !reply.is_ok() {
            return Err(reply.error(&format!("sending to {recipient}")));
        }
    }
    session.expect("DATA", 354, "sending the message")?;
    session.write_raw(&data(message))
}

fn check_envelope(from: &str, recipients: &[String]) -> Result<()> {
    if recipients.is_empty() {
        bail!("The message has no recipients.");
    }
    for address in std::iter::once(from).chain(recipients.iter().map(String::as_str)) {
        if !is_plain_address(address) {
            bail!("“{}” is not an email address.", mail::sanitize(address));
        }
    }
    Ok(())
}

fn is_plain_address(address: &str) -> bool {
    mail::is_address(address) && !address.contains(['<', '>', '\r', '\n'])
}

/// The message as DATA carries it: CRLF line endings, a dot doubled at the start of a
/// line, and ending with a line break (the final dot is sent on its own).
fn data(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + message.len() / 32 + 2);
    let mut line_start = true;
    let mut bytes = message.iter().copied().peekable();
    while let Some(byte) = bytes.next() {
        match byte {
            b'\r' => {
                bytes.next_if_eq(&b'\n');
                out.extend_from_slice(b"\r\n");
                line_start = true;
            }
            b'\n' => {
                out.extend_from_slice(b"\r\n");
                line_start = true;
            }
            _ => {
                if line_start && byte == b'.' {
                    out.push(b'.');
                }
                out.push(byte);
                line_start = false;
            }
        }
    }
    if !line_start {
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// What the server said it can do, in its answer to EHLO.
#[derive(Debug, Default, PartialEq)]
struct Extensions {
    starttls: bool,
    eight_bit: bool,
    /// The sign-in methods offered, upper case.
    auth: Vec<String>,
}

impl Extensions {
    fn parse(lines: &[String]) -> Self {
        let mut extensions = Extensions::default();
        // The first line is the server's name.
        for line in lines.iter().skip(1) {
            let line = line.to_ascii_uppercase();
            let mut words = line.split_ascii_whitespace();
            match words.next() {
                Some("STARTTLS") => extensions.starttls = true,
                Some("8BITMIME") => extensions.eight_bit = true,
                // Some old servers say `AUTH=LOGIN`.
                Some(word) if word == "AUTH" || word.starts_with("AUTH=") => {
                    let first = word.strip_prefix("AUTH=").filter(|w| !w.is_empty());
                    extensions
                        .auth
                        .extend(first.into_iter().chain(words).map(str::to_string));
                }
                _ => {}
            }
        }
        extensions
    }

    fn offers_auth(&self, method: &str) -> bool {
        self.auth.iter().any(|m| m == method)
    }
}

/// One answer: its code and the text of each of its lines.
#[derive(Debug)]
struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    fn is_ok(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// The server's own words, safe to show.
    fn text(&self) -> String {
        clean(&self.lines.join(" "))
    }

    fn error(&self, what: &str) -> anyhow::Error {
        anyhow!(
            "The mail server refused {what}: {} {}",
            self.code,
            self.text()
        )
    }
}

/// Printable characters only, cut short.
fn clean(text: &str) -> String {
    let text: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match text.char_indices().nth(MAX_TEXT) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text,
    }
}

/// A connection being spoken to: over TLS, or plain until STARTTLS (and in tests, anything
/// that reads and writes).
struct Session<S> {
    stream: S,
}

impl<S: Read + Write> Session<S> {
    fn new(stream: S) -> Self {
        Session { stream }
    }

    /// The server's first words.
    fn greeting(&mut self) -> Result<()> {
        let reply = self.reply()?;
        if reply.code != 220 {
            return Err(reply.error("the connection"));
        }
        Ok(())
    }

    fn ehlo(&mut self) -> Result<Extensions> {
        let reply = self.expect(&format!("EHLO {HELLO_NAME}"), 250, "the greeting (EHLO)")?;
        Ok(Extensions::parse(&reply.lines))
    }

    /// Says goodbye, without minding whether the server answers.
    fn quit(&mut self) {
        let _ = self.command("QUIT");
    }

    /// Sends a command and expects `code` back.
    fn expect(&mut self, line: &str, code: u16, what: &str) -> Result<Reply> {
        let reply = self.command(line)?;
        if reply.code != code {
            return Err(reply.error(what));
        }
        Ok(reply)
    }

    /// Sends one command line and reads the answer. The line is never put in an error: it
    /// may be a password.
    fn command(&mut self, line: &str) -> Result<Reply> {
        let mut bytes = Vec::with_capacity(line.len() + 2);
        bytes.extend_from_slice(line.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        self.write_raw(&bytes)?;
        self.reply()
    }

    fn write_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.stream
            .write_all(bytes)
            .and_then(|()| self.stream.flush())
            .map_err(|error| lost(&error))
    }

    /// One answer, of one line or several (`250-…` lines, then a last `250 …`).
    fn reply(&mut self) -> Result<Reply> {
        let mut code = None;
        let mut lines = Vec::new();
        loop {
            let line = self.read_line()?;
            let digits = line.get(..3).filter(|d| d.iter().all(u8::is_ascii_digit));
            let Some(digits) = digits else {
                bail!("The mail server answered something unexpected.");
            };
            let this = digits
                .iter()
                .fold(0u16, |n, d| n * 10 + u16::from(d - b'0'));
            if *code.get_or_insert(this) != this {
                bail!("The mail server answered something unexpected.");
            }
            lines.push(String::from_utf8_lossy(line.get(4..).unwrap_or_default()).into_owned());
            match line.get(3) {
                None | Some(b' ') => break,
                Some(b'-') if lines.len() < MAX_LINES => {}
                Some(b'-') => bail!("The mail server’s answer was too long."),
                Some(_) => bail!("The mail server answered something unexpected."),
            }
        }
        Ok(Reply {
            code: code.unwrap_or_default(),
            lines,
        })
    }

    /// One line, without its line break. Read a byte at a time, so that nothing after it
    /// is taken from the connection (which matters before STARTTLS).
    fn read_line(&mut self) -> Result<Vec<u8>> {
        let mut line = Vec::new();
        let mut byte = [0u8];
        loop {
            match self.stream.read(&mut byte) {
                Ok(0) => {
                    return Err(anyhow!(Offline).context("the mail server closed the connection"));
                }
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) if line.len() >= MAX_LINE => {
                    bail!("The mail server answered with a line too long to read.");
                }
                Ok(_) => line.push(byte[0]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(lost(&error)),
            }
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(line)
    }
}

/// The connection failing part way: as good as being offline.
fn lost(error: &io::Error) -> anyhow::Error {
    anyhow!(Offline).context(format!(
        "the connection to the mail server was lost ({error})"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A server that answers with what it was given, in order, and keeps what it is sent.
    struct Fake {
        answers: Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }

    impl Fake {
        fn new(answers: &str) -> Session<Fake> {
            Session::new(Fake {
                answers: Cursor::new(answers.as_bytes().to_vec()),
                sent: Vec::new(),
            })
        }
    }

    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.answers.read(buf)
        }
    }

    impl Write for Fake {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.sent.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn pw(password: &str) -> Secret {
        Secret::Password(password.into())
    }

    fn sent(session: &Session<Fake>) -> String {
        String::from_utf8(session.stream.sent.clone()).unwrap()
    }

    const EHLO: &str = "250-mail.example.com Hello\r\n250-PIPELINING\r\n250-SIZE 35882577\r\n\
                        250-AUTH LOGIN PLAIN\r\n250 8BITMIME\r\n";

    fn recipients(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_message_is_sent_with_the_exact_commands() {
        let answers = format!(
            "220 mail.example.com ESMTP\r\n{EHLO}235 OK\r\n250 OK\r\n250 OK\r\n250 OK\r\n\
             354 Go ahead\r\n250 Queued as 12345\r\n221 Bye\r\n"
        );
        let mut session = Fake::new(&answers);
        session.greeting().unwrap();
        let extensions = signed_in(&mut session, "me@example.com", &pw("secret")).unwrap();
        let message = b"Subject: Hi\nTo: a@example.com\n\n.hidden\r\n..two\rlast";
        deliver(
            &mut session,
            &extensions,
            "me@example.com",
            &recipients(&["a@example.com", "b@example.org"]),
            message,
        )
        .unwrap();
        session.quit();
        let token = STANDARD.encode("\0me@example.com\0secret");
        assert_eq!(
            sent(&session),
            format!(
                "EHLO [127.0.0.1]\r\nAUTH PLAIN {token}\r\nMAIL FROM:<me@example.com>\r\n\
                 RCPT TO:<a@example.com>\r\nRCPT TO:<b@example.org>\r\nDATA\r\n\
                 Subject: Hi\r\nTo: a@example.com\r\n\r\n..hidden\r\n...two\r\nlast\r\n.\r\nQUIT\r\n"
            )
        );
    }

    #[test]
    fn a_message_with_eight_bit_text_says_so_when_the_server_allows_it() {
        let mut session = Fake::new("250 OK\r\n250 OK\r\n354 Go\r\n250 OK\r\n");
        let extensions = Extensions {
            eight_bit: true,
            ..Extensions::default()
        };
        let to = recipients(&["a@example.com"]);
        deliver(
            &mut session,
            &extensions,
            "me@example.com",
            &to,
            "Hé\r\n".as_bytes(),
        )
        .unwrap();
        assert!(sent(&session).starts_with("MAIL FROM:<me@example.com> BODY=8BITMIME\r\n"));
    }

    #[test]
    fn data_ends_lines_with_crlf_and_doubles_leading_dots() {
        assert_eq!(data(b"a\nb\r\nc\rd"), b"a\r\nb\r\nc\r\nd\r\n");
        assert_eq!(data(b".\n.a\nb.c\r\n"), b"..\r\n..a\r\nb.c\r\n");
        assert_eq!(data(b"x\r\n"), b"x\r\n");
        assert_eq!(data(b""), b"");
        assert_eq!(data(b"\r\r\n"), b"\r\n\r\n");
    }

    #[test]
    fn a_multi_line_ehlo_answer_is_read_whole() {
        let mut session = Fake::new(&format!("{EHLO}250 next\r\n"));
        let extensions = session.ehlo().unwrap();
        assert_eq!(
            extensions,
            Extensions {
                starttls: false,
                eight_bit: true,
                auth: vec!["LOGIN".into(), "PLAIN".into()],
            }
        );
        // Only the one answer was read.
        assert_eq!(session.reply().unwrap().lines, ["next"]);

        let old = Extensions::parse(&["host".into(), "AUTH=LOGIN".into(), "starttls".into()]);
        assert!(old.offers_auth("LOGIN") && old.starttls);
    }

    #[test]
    fn answers_that_do_not_follow_the_rules_are_refused() {
        for answer in [
            "250-one\r\n354 two\r\n",
            "hello\r\n",
            "25\r\n",
            "250*odd\r\n",
            "250-one\r\n",
        ] {
            assert!(Fake::new(answer).reply().is_err(), "{answer:?}");
        }
        let long = format!("250 {}\r\n", "x".repeat(MAX_LINE + 10));
        assert!(Fake::new(&long).reply().is_err());
        let many = "250-x\r\n".repeat(MAX_LINES + 1) + "250 x\r\n";
        assert!(Fake::new(&many).reply().is_err());
        // A bare 250, and a line ending in LF alone, are fine.
        assert_eq!(Fake::new("250\n").reply().unwrap().code, 250);
    }

    #[test]
    fn auth_login_is_used_when_plain_is_not_offered() {
        let mut session = Fake::new(
            "250-mail.example.com\r\n250 AUTH LOGIN\r\n334 VXNlcm5hbWU6\r\n334 UGFzc3dvcmQ6\r\n235 OK\r\n",
        );
        signed_in(&mut session, "me", &pw("pa ss")).unwrap();
        assert_eq!(
            sent(&session),
            format!(
                "EHLO [127.0.0.1]\r\nAUTH LOGIN\r\n{}\r\n{}\r\n",
                STANDARD.encode("me"),
                STANDARD.encode("pa ss")
            )
        );
    }

    #[test]
    fn a_rejected_password_is_auth_failed() {
        let mut session = Fake::new(&format!("{EHLO}535 5.7.8 Authentication failed\r\n"));
        let error = signed_in(&mut session, "me", &pw("wrong")).unwrap_err();
        assert!(error.is::<AuthFailed>());
        assert!(!format!("{error:#}").contains("wrong"));

        let mut session =
            Fake::new("250-x\r\n250 AUTH LOGIN\r\n334 VXNlcm5hbWU6\r\n535 No such user\r\n");
        assert!(
            signed_in(&mut session, "me", &pw("pw"))
                .unwrap_err()
                .is::<AuthFailed>()
        );
        // The password was not sent once the user name was refused.
        assert!(!sent(&session).contains(&STANDARD.encode("pw")));

        let mut session = Fake::new("250-x\r\n250 SIZE 10\r\n");
        let error = signed_in(&mut session, "me", &pw("pw")).unwrap_err();
        assert!(!error.is::<AuthFailed>());
        assert_eq!(sent(&session), "EHLO [127.0.0.1]\r\n");
    }

    #[test]
    fn a_token_signs_in_with_xoauth2() {
        let mut session = Fake::new("250-x\r\n250 AUTH LOGIN XOAUTH2\r\n235 2.7.0 OK\r\n");
        let token = Secret::Bearer("EwBtoken".into());
        signed_in(&mut session, "ana@outlook.com", &token).unwrap();
        let initial = STANDARD.encode("user=ana@outlook.com\x01auth=Bearer EwBtoken\x01\x01");
        assert_eq!(
            sent(&session),
            format!("EHLO [127.0.0.1]\r\nAUTH XOAUTH2 {initial}\r\n")
        );

        // Refused: the challenge is answered with an empty line, then the server says no.
        let challenge = STANDARD.encode(r#"{"status":"401","schemes":"bearer"}"#);
        let mut session = Fake::new(&format!(
            "250-x\r\n250 AUTH XOAUTH2\r\n334 {challenge}\r\n535 5.7.3 Authentication unsuccessful\r\n"
        ));
        let error = signed_in(&mut session, "ana@outlook.com", &token).unwrap_err();
        assert!(error.is::<AuthFailed>());
        assert!(sent(&session).ends_with(&format!("AUTH XOAUTH2 {initial}\r\n\r\n")));
        assert!(!format!("{error:#}").contains("EwBtoken"));

        // Not offered: nothing is sent.
        let mut session = Fake::new(EHLO);
        assert!(signed_in(&mut session, "ana@outlook.com", &token).is_err());
        assert_eq!(sent(&session), "EHLO [127.0.0.1]\r\n");
    }

    #[test]
    fn a_rejected_recipient_stops_the_send() {
        let mut session =
            Fake::new("250 OK\r\n250 OK\r\n550 5.1.1 <b@example.org>: no\x07 such\r\n  user\r\n");
        let to = recipients(&["a@example.com", "b@example.org"]);
        let error = deliver(
            &mut session,
            &Extensions::default(),
            "me@example.com",
            &to,
            b"x",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("550") && text.contains("b@example.org"),
            "{text}"
        );
        assert!(!text.chars().any(char::is_control), "{text:?}");
        assert!(!error.is::<MayHaveArrived>());
        assert!(!sent(&session).contains("DATA"));
    }

    #[test]
    fn bad_addresses_are_refused_before_anything_is_said() {
        for (from, to) in [
            ("me@example.com", vec![]),
            ("me@example.com", vec!["a@example.com>\r\nRSET"]),
            ("me@example.com", vec!["<a@example.com>"]),
            ("me@example.com>", vec!["a@example.com"]),
            ("nobody", vec!["a@example.com"]),
        ] {
            let mut session = Fake::new("250 OK\r\n250 OK\r\n354 Go\r\n250 OK\r\n");
            let to = recipients(&to);
            assert!(deliver(&mut session, &Extensions::default(), from, &to, b"x").is_err());
            assert!(sent(&session).is_empty(), "{from} {to:?}");
        }
    }

    #[test]
    fn a_connection_lost_after_the_final_dot_may_have_sent() {
        let to = recipients(&["a@example.com"]);
        let mut session = Fake::new("250 OK\r\n250 OK\r\n354 Go\r\n");
        let error = deliver(
            &mut session,
            &Extensions::default(),
            "me@example.com",
            &to,
            b"x",
        )
        .unwrap_err();
        assert!(error.is::<MayHaveArrived>() && error.is::<Offline>());
        assert!(sent(&session).ends_with("x\r\n.\r\n"));

        // Lost before it: nothing was sent.
        let mut session = Fake::new("250 OK\r\n250 OK\r\n");
        let error = deliver(
            &mut session,
            &Extensions::default(),
            "me@example.com",
            &to,
            b"x",
        )
        .unwrap_err();
        assert!(error.is::<Offline>() && !error.is::<MayHaveArrived>());

        // Refused after it: not sent either.
        let mut session = Fake::new("250 OK\r\n250 OK\r\n354 Go\r\n554 Spam\r\n");
        let error = deliver(
            &mut session,
            &Extensions::default(),
            "me@example.com",
            &to,
            b"x",
        )
        .unwrap_err();
        assert!(!error.is::<MayHaveArrived>() && !error.is::<Offline>());
    }

    #[test]
    fn a_server_without_starttls_is_refused_before_signing_in() {
        let mut session = Fake::new(&format!("220 hi\r\n{EHLO}"));
        let error = start_tls(&mut session).unwrap_err();
        assert!(error.to_string().contains("STARTTLS"));
        assert_eq!(sent(&session), "EHLO [127.0.0.1]\r\n");
    }

    #[test]
    fn nothing_past_the_starttls_answer_is_read() {
        let answers = "220 hi\r\n250-x\r\n250 STARTTLS\r\n220 Go ahead\r\n\x16\x03\x03TLS";
        let mut session = Fake::new(answers);
        start_tls(&mut session).unwrap();
        assert_eq!(sent(&session), "EHLO [127.0.0.1]\r\nSTARTTLS\r\n");
        let read = session.stream.answers.position() as usize;
        assert_eq!(&answers[read..], "\x16\x03\x03TLS");
    }

    #[test]
    fn what_the_server_says_is_cleaned() {
        assert_eq!(clean("bad\x1b[31m\r\nthing\t here"), "bad [31m thing here");
        assert_eq!(clean(&"é".repeat(500)).chars().count(), MAX_TEXT + 1);
    }
}
