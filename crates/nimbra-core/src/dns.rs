//! A small DNS client that asks the system's resolvers for a domain's MX records (its mail
//! servers), so a custom domain can be matched to the provider that hosts its mail.
//!
//! Security notes:
//! - Only the domain is sent, and only to the resolvers the system itself uses (from
//!   `/etc/resolv.conf`), as any app looking up a name would.
//! - Each query has a random id, and a reply is only read when its id and question match
//!   the query; anything else from the resolver's address is ignored until the time runs
//!   out. The socket is connected, so packets from other addresses are dropped.
//! - Replies are untrusted input: every read is bounds-checked, compression pointers must
//!   point backwards (so they cannot loop), names are capped at 255 bytes and labels at 63,
//!   and labels may only hold printable ASCII other than `.`. A bad reply is an error, never
//!   a panic. Host names still go through `servers::is_host` before they are used.
//! - Plain DNS is neither encrypted nor signed here, so an attacker on the network can
//!   forge an answer. The answer only chooses which provider to suggest; the connection
//!   that follows is still checked with TLS against the host name.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail, ensure};

/// How long to wait for one resolver.
const PER_RESOLVER: Duration = Duration::from_secs(3);
/// How long a whole lookup may take, across resolvers.
const TOTAL: Duration = Duration::from_secs(6);
/// The longest a name may be on the wire, length bytes included (RFC 1035).
const MAX_NAME: usize = 255;
/// The longest a label may be (RFC 1035).
const MAX_LABEL: usize = 63;
/// Resolvers tried, as the system's own resolver does (`MAXNS`).
const MAX_RESOLVERS: usize = 3;

const TYPE_CNAME: u16 = 5;
const TYPE_MX: u16 = 15;
const CLASS_IN: u16 = 1;
const RCODE_NXDOMAIN: u16 = 3;

/// The mail servers of `domain`, lowercase, most preferred first. Empty when the domain
/// has none. Blocks for up to six seconds.
pub fn mx(domain: &str) -> Result<Vec<String>> {
    let conf = std::fs::read_to_string("/etc/resolv.conf").context("reading /etc/resolv.conf")?;
    let resolvers = resolvers(&conf);
    if resolvers.is_empty() {
        bail!("no DNS resolver is set up");
    }
    let deadline = Instant::now() + TOTAL;
    let mut last = anyhow!("no DNS resolver answered");
    for resolver in resolvers {
        match ask(resolver, domain, deadline) {
            Ok(hosts) => return Ok(hosts),
            Err(error) => last = error,
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    Err(last)
}

/// One query to one resolver, waiting until the reply or the time limit.
fn ask(resolver: SocketAddr, domain: &str, deadline: Instant) -> Result<Vec<String>> {
    let mut id = [0u8; 2];
    getrandom::getrandom(&mut id).map_err(|e| anyhow!("no secure random source: {e}"))?;
    let id = u16::from_be_bytes(id);
    let packet = query(id, domain)?;
    let local: IpAddr = match resolver {
        SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let socket = UdpSocket::bind((local, 0))?;
    socket.connect(resolver)?;
    socket.send(&packet)?;
    let until = deadline.min(Instant::now() + PER_RESOLVER);
    let mut buffer = [0u8; 4096];
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left < Duration::from_millis(1) {
            bail!("the DNS resolver did not answer in time");
        }
        socket.set_read_timeout(Some(left))?;
        let size = socket.recv(&mut buffer)?;
        let reply = &buffer[..size];
        // A stray or forged packet: keep waiting for the real one.
        if reply.len() < 2 || u16::from_be_bytes([reply[0], reply[1]]) != id {
            continue;
        }
        return parse(reply, id, domain);
    }
}

/// The resolvers named in `resolv.conf`, on port 53. Addresses with a zone (`fe80::1%en0`)
/// are left out.
fn resolvers(conf: &str) -> Vec<SocketAddr> {
    let mut found: Vec<SocketAddr> = Vec::new();
    for line in conf.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let Some(Ok(ip)) = words.next().map(str::parse::<IpAddr>) else {
            continue;
        };
        let address = SocketAddr::new(ip, 53);
        if !found.contains(&address) {
            found.push(address);
        }
    }
    found.truncate(MAX_RESOLVERS);
    found
}

/// The query packet: header with recursion desired, then one question for `domain`'s MX
/// records.
fn query(id: u16, domain: &str) -> Result<Vec<u8>> {
    let domain = domain.trim_end_matches('.');
    ensure!(
        crate::servers::is_host(domain) && domain.parse::<IpAddr>().is_err(),
        "not a domain name"
    );
    let mut packet = Vec::with_capacity(18 + domain.len());
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    packet.extend_from_slice(&1u16.to_be_bytes()); // one question
    packet.extend_from_slice(&[0; 6]); // no answer, authority or additional records
    for label in domain.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&TYPE_MX.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(packet)
}

/// The MX hosts in a reply to `query(id, domain)`, most preferred first. Records for other
/// names are ignored, except along a CNAME chain from `domain`.
fn parse(reply: &[u8], id: u16, domain: &str) -> Result<Vec<String>> {
    let mut reader = Reader { data: reply, at: 0 };
    ensure!(reader.u16()? == id, "the DNS reply is for another query");
    let flags = reader.u16()?;
    ensure!(flags & 0x8000 != 0, "the DNS packet is not a reply");
    ensure!(
        flags & 0x7800 == 0,
        "the DNS reply has an unexpected opcode"
    );
    let truncated = flags & 0x0200 != 0;
    let questions = reader.u16()?;
    let answers = reader.u16()?;
    reader.skip(4)?;
    ensure!(questions == 1, "the DNS reply does not repeat the question");
    let asked = domain.trim_end_matches('.').to_ascii_lowercase();
    ensure!(
        reader.name()? == asked && reader.u16()? == TYPE_MX && reader.u16()? == CLASS_IN,
        "the DNS reply is for another question"
    );
    match flags & 0x000f {
        0 => {}
        RCODE_NXDOMAIN => return Ok(Vec::new()),
        code => bail!("the DNS resolver failed (code {code})"),
    }
    let mut names = vec![asked];
    let mut found: Vec<(u16, String)> = Vec::new();
    for _ in 0..answers {
        match record(&mut reader, &mut names, &mut found) {
            Ok(()) => {}
            // A cut-off reply: keep what came through whole.
            Err(_) if truncated => break,
            Err(error) => return Err(error),
        }
    }
    found.sort_by_key(|(preference, _)| *preference);
    let mut hosts: Vec<String> = Vec::new();
    for (_, host) in found {
        if !host.is_empty() && !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    Ok(hosts)
}

/// Reads one answer record, keeping MX hosts for any name in `names` and following CNAMEs.
fn record(
    reader: &mut Reader,
    names: &mut Vec<String>,
    found: &mut Vec<(u16, String)>,
) -> Result<()> {
    let owner = reader.name()?;
    let kind = reader.u16()?;
    let class = reader.u16()?;
    reader.skip(4)?; // TTL
    let length = reader.u16()? as usize;
    let end = reader
        .at
        .checked_add(length)
        .filter(|end| *end <= reader.data.len())
        .ok_or_else(|| anyhow!("a DNS record runs past the reply"))?;
    let ours = class == CLASS_IN && names.contains(&owner);
    if ours && kind == TYPE_MX {
        let preference = reader.u16()?;
        let host = reader.name()?;
        ensure!(reader.at == end, "a DNS MX record has the wrong length");
        found.push((preference, host));
    } else if ours && kind == TYPE_CNAME {
        let target = reader.name()?;
        ensure!(reader.at == end, "a DNS CNAME record has the wrong length");
        if !names.contains(&target) {
            names.push(target);
        }
    }
    reader.at = end;
    Ok(())
}

/// A cursor over a reply that never reads past its end.
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> Result<u8> {
        let byte = *self
            .data
            .get(self.at)
            .ok_or_else(|| anyhow!("the DNS reply is cut short"))?;
        self.at += 1;
        Ok(byte)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }

    fn skip(&mut self, count: usize) -> Result<()> {
        ensure!(
            self.data.len().saturating_sub(self.at) >= count,
            "the DNS reply is cut short"
        );
        self.at += count;
        Ok(())
    }

    /// A name, lowercase and without the final dot (`""` for the root), following
    /// compression pointers. The cursor ends after the name's first pointer or its end.
    fn name(&mut self) -> Result<String> {
        let mut name = String::new();
        let mut wire = 0;
        let mut at = self.at;
        let mut resume = None;
        loop {
            let length = *self
                .data
                .get(at)
                .ok_or_else(|| anyhow!("a DNS name runs past the reply"))?;
            match length & 0xc0 {
                0xc0 => {
                    let low = *self
                        .data
                        .get(at + 1)
                        .ok_or_else(|| anyhow!("a DNS name runs past the reply"))?;
                    let target = usize::from(u16::from_be_bytes([length & 0x3f, low]));
                    // Only backwards, so pointers cannot go round in a loop.
                    ensure!(target < at, "a DNS name points forwards");
                    resume.get_or_insert(at + 2);
                    at = target;
                }
                0x00 => {
                    let length = usize::from(length);
                    wire += length + 1;
                    ensure!(wire <= MAX_NAME, "a DNS name is too long");
                    if length == 0 {
                        break;
                    }
                    ensure!(length <= MAX_LABEL, "a DNS label is too long");
                    let label = self
                        .data
                        .get(at + 1..at + 1 + length)
                        .ok_or_else(|| anyhow!("a DNS name runs past the reply"))?;
                    ensure!(
                        label.iter().all(|b| b.is_ascii_graphic() && *b != b'.'),
                        "a DNS name has an unexpected character"
                    );
                    if !name.is_empty() {
                        name.push('.');
                    }
                    name.extend(label.iter().map(|b| b.to_ascii_lowercase() as char));
                    at += 1 + length;
                }
                _ => bail!("a DNS name has an unknown label type"),
            }
        }
        self.at = resume.unwrap_or(at + 1);
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply to `query(0xbeef, "example.com")` with two MX records, the second listed
    /// first by preference, both using compression as real resolvers do.
    fn reply() -> Vec<u8> {
        let mut packet = query(0xbeef, "example.com").unwrap();
        packet[2] = 0x81; // QR, RD
        packet[3] = 0x80; // RA, no error
        packet[7] = 2; // two answers
        // Answer 1: example.com MX 20 alt.mx.example.net
        packet.extend_from_slice(&[0xc0, 12, 0, 15, 0, 1, 0, 0, 0x0e, 0x10]);
        let rdata: &[u8] = b"\x00\x14\x03alt\x02mx\x07example\x03net\x00";
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        let alt_mx = packet.len() + 6; // where "mx.example.net" starts
        packet.extend_from_slice(rdata);
        // Answer 2: example.com MX 10 main.<mx.example.net>
        packet.extend_from_slice(&[0xc0, 12, 0, 15, 0, 1, 0, 0, 0x0e, 0x10]);
        let mut rdata = b"\x00\x0a\x04MAIN".to_vec();
        rdata.extend_from_slice(&[0xc0 | (alt_mx >> 8) as u8, alt_mx as u8]);
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&rdata);
        packet
    }

    #[test]
    fn the_query_packet_is_built_by_the_book() {
        let packet = query(0x1234, "Mail.Example.com.").unwrap();
        let mut expected = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        expected.extend_from_slice(b"\x04Mail\x07Example\x03com\x00");
        expected.extend_from_slice(&[0, 15, 0, 1]);
        assert_eq!(packet, expected);
        for bad in ["", "a b.com", "127.0.0.1", "a..b", &"x".repeat(64)] {
            assert!(query(1, bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_compressed_reply_is_read_and_sorted_by_preference() {
        assert_eq!(
            parse(&reply(), 0xbeef, "Example.com").unwrap(),
            ["main.mx.example.net", "alt.mx.example.net"]
        );
    }

    #[test]
    fn mx_records_follow_a_cname_and_ignore_other_names() {
        let mut packet = query(7, "a.org").unwrap();
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[7] = 3;
        // a.org CNAME b.org
        packet.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 1, 0, 7]);
        packet.extend_from_slice(b"\x01b\x03org\x00");
        // evil.org MX 0 evil.org (not ours)
        packet.extend_from_slice(b"\x04evil\x03org\x00");
        packet.extend_from_slice(&[0, 15, 0, 1, 0, 0, 0, 1, 0, 4, 0, 0, 0xc0, 42]);
        // b.org MX 5 mx.b.org
        packet.extend_from_slice(&[0xc0, 35, 0, 15, 0, 1, 0, 0, 0, 1, 0, 7, 0, 5, 2, b'm', b'x']);
        packet.extend_from_slice(&[0xc0, 35]);
        assert_eq!(parse(&packet, 7, "a.org").unwrap(), ["mx.b.org"]);
    }

    #[test]
    fn no_such_domain_and_null_mx_give_no_hosts() {
        let mut packet = query(9, "none.example").unwrap();
        packet[2] = 0x81;
        packet[3] = 0x83; // NXDOMAIN
        assert_eq!(
            parse(&packet, 9, "none.example").unwrap(),
            Vec::<String>::new()
        );
        // RFC 7505: "MX 0 ." means the domain takes no mail.
        let mut packet = query(9, "none.example").unwrap();
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[7] = 1;
        packet.extend_from_slice(&[0xc0, 12, 0, 15, 0, 1, 0, 0, 0, 1, 0, 3, 0, 0, 0]);
        assert_eq!(
            parse(&packet, 9, "none.example").unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn bad_replies_are_errors() {
        let good = reply();
        // Wrong id, another question, a query rather than a reply, a server failure.
        assert!(parse(&good, 0xbeee, "example.com").is_err());
        assert!(parse(&good, 0xbeef, "example.org").is_err());
        let mut not_reply = good.clone();
        not_reply[2] &= 0x7f;
        assert!(parse(&not_reply, 0xbeef, "example.com").is_err());
        let mut failed = good.clone();
        failed[3] = 0x82;
        assert!(parse(&failed, 0xbeef, "example.com").is_err());
        // Every cut-off length is an error; with the truncated flag set, whole answers
        // before the cut are kept and nothing panics.
        for size in 0..good.len() {
            assert!(
                parse(&good[..size], 0xbeef, "example.com").is_err(),
                "{size}"
            );
            let mut cut = good[..size].to_vec();
            if cut.len() > 2 {
                cut[2] |= 0x02;
            }
            let _ = parse(&cut, 0xbeef, "example.com");
        }
        let first_answer = query(0xbeef, "example.com").unwrap().len() + 34;
        let mut cut = good[..first_answer + 3].to_vec();
        cut[2] |= 0x02;
        assert_eq!(
            parse(&cut, 0xbeef, "example.com").unwrap(),
            ["alt.mx.example.net"]
        );
    }

    #[test]
    fn hostile_names_are_errors_not_panics() {
        let base = || {
            let mut packet = query(1, "x.com").unwrap();
            packet[2] = 0x81;
            packet[3] = 0x80;
            packet[7] = 1;
            packet.extend_from_slice(&[0xc0, 12, 0, 15, 0, 1, 0, 0, 0, 1]);
            packet
        };
        let answer = |rdata: &[u8]| {
            let mut packet = base();
            packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            packet.extend_from_slice(rdata);
            packet
        };
        // A pointer to itself, a pointer forwards, a pointer out of the packet.
        let here = base().len() + 2 + 2;
        let selfish = answer(&[0, 1, 0xc0 | (here >> 8) as u8, here as u8]);
        assert!(parse(&selfish, 1, "x.com").is_err());
        assert!(parse(&answer(&[0, 1, 0xc0, 0xff]), 1, "x.com").is_err());
        assert!(parse(&answer(&[0, 1, 0xff, 0xff]), 1, "x.com").is_err());
        // Reserved label types.
        assert!(parse(&answer(&[0, 1, 0x40, 0]), 1, "x.com").is_err());
        assert!(parse(&answer(&[0, 1, 0x80, 0]), 1, "x.com").is_err());
        // A name longer than 255 bytes.
        let mut long = vec![0, 1];
        for _ in 0..5 {
            long.push(60);
            long.extend_from_slice(&[b'a'; 60]);
        }
        long.push(0);
        assert!(parse(&answer(&long), 1, "x.com").is_err());
        // A dot or a control character inside a label.
        assert!(parse(&answer(b"\x00\x01\x03a.b\x00"), 1, "x.com").is_err());
        assert!(parse(&answer(b"\x00\x01\x03a\nb\x00"), 1, "x.com").is_err());
        // An rdata length that runs past the end, or does not fit the name.
        let mut over = base();
        over.extend_from_slice(&[0x10, 0x00, 0, 1, 0]);
        assert!(parse(&over, 1, "x.com").is_err());
        assert!(parse(&answer(b"\x00\x01\x01a\x00\x00"), 1, "x.com").is_err());
        // A question that points into the header.
        let mut looped = query(1, "x.com").unwrap();
        looped[2] = 0x81;
        looped[12] = 0xc0;
        looped[13] = 12;
        assert!(parse(&looped, 1, "x.com").is_err());
    }

    #[test]
    fn resolvers_come_from_resolv_conf() {
        let conf = "# macOS\nsearch example.com\nnameserver 192.168.1.1\nnameserver  fd00::53 \n\
                    nameserver fe80::1%en0\nnameserver nonsense\nnameserver 192.168.1.1\n\
                    nameserver 1.1.1.1\nnameserver 8.8.8.8\n";
        let found: Vec<String> = resolvers(conf).iter().map(ToString::to_string).collect();
        assert_eq!(found, ["192.168.1.1:53", "[fd00::53]:53", "1.1.1.1:53"]);
        assert!(resolvers("search example.com\n").is_empty());
    }

    /// Run by hand: `cargo test -- --ignored live_mx`.
    #[test]
    #[ignore = "needs the network"]
    fn live_mx_lookup() {
        let hosts = mx("zoho.com").unwrap();
        println!("zoho.com MX: {hosts:?}");
        assert!(!hosts.is_empty());
        assert!(hosts.iter().all(|host| host.contains("zoho")), "{hosts:?}");
    }
}
