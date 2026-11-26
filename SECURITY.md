# Security policy

nimbra-core is the mail engine of Nimbra's apps: it holds the code that reads untrusted mail, signs in, keeps the
sign-ins and passwords, encrypts the local store and sends. We take security reports seriously. Thanks for helping
keep it safe.

## Supported versions

| Version | Fixes |
| --- | --- |
| The latest tag | ✅ |
| `main` | ✅ |
| Anything older | ❌ Update first |

## Reporting a vulnerability

**Please don't open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub: [Report a vulnerability](https://github.com/nimbra-mail/core/security/advisories/new)
(the repository's **Security** tab › **Report a vulnerability**). The report stays private between you, the
maintainers and anyone we invite to help fix it.

Please include:

- what an attacker can do, and what they need first (an email they send you, a network they control, local access…);
- the steps to reproduce it, and a proof of concept if you have one (a crafted `.eml` is ideal);
- the nimbra-core version or commit, and which app (macOS or iOS) and system version you saw it on;
- anything you've already found about the cause.

## What to expect

These are aims rather than promises:

- We confirm we've received your report within a week.
- We tell you whether we can reproduce it and how serious we think it is, and keep you posted while we fix it.
- We aim to ship a fix for a confirmed serious problem within 30 days, usually much sooner.
- When the fix is out, we publish a GitHub Security Advisory and credit you by name, unless you'd rather we didn't.

Please give us a reasonable chance to ship a fix before you publish anything, and tell us when you plan to.

## Scope

In scope:

- **Untrusted email.** Parsing a received message (MIME, HTML to text blocks, attachments, file names): crashes,
  runaway memory or time, links or images that get past the sanitising, unsafe file names.
- **Secrets.** Sign-ins, refresh tokens, passwords and the store's key leaving the Keychain (or the app's
  `SecretStore`), or being logged, put into an error or written to disk.
- **The local store.** Reading the encrypted store without its key, or anything written there in the clear.
- **Sign-in.** The Google and Microsoft OAuth flows (PKCE, `state`, the loopback redirect on the Mac and the
  custom-scheme redirect on iOS), and taking over another account.
- **Transport.** IMAP and SMTP without certificate checks or downgraded to plain text; requests to hosts other than
  the ones a feature needs.
- **Sending.** Mail sent without the user asking, to the wrong recipients, from the wrong account, or twice.
- **The Swift boundary.** Anything the generated bindings let a caller do that the Rust API does not.

Elsewhere:

- A bug in rustls, ureq, mail-parser, UniFFI or another dependency belongs to that project; report it there. If
  nimbra-core hasn't picked up a published fix yet, that's ours, so tell us.
- Not counted: attacks that need someone who already controls your device or your unlocked account, social
  engineering, and missing hardening with no real way to attack it.

## Safe harbor

We won't take legal action against you, or ask anyone else to, for security research done in good faith under this
policy. Good faith means you test only against your own accounts, devices and data, don't keep or share data that
isn't yours, and give us a reasonable chance to fix the problem before you publish anything.

If you're not sure whether something is allowed, ask us in your report first.
