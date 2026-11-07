//! The DNS forwarder. nftables redirects every DNS query a sandbox sends,
//! over UDP or TCP, to it. It checks the name against the sandbox's egress
//! policy, sends allowed queries to the upstream resolver, and reports each
//! query.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::policy::normalize_host;
use crate::proxy::{Activity, Inner, Registration};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// A TCP client that sends nothing for this long is closed.
const TCP_IDLE: Duration = Duration::from_secs(10);
const MAX_MESSAGE: usize = 65_535;
/// Answers kept in an event.
const MAX_ANSWERS: usize = 16;

const HEADER_LEN: usize = 12;
const SERVFAIL: u8 = 2;
const REFUSED: u8 = 5;

/// The question of a query: its name, type and where the question ends.
#[derive(Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    end: usize,
}

/// Reads the first question. `None` if `msg` is not a query with one.
pub fn question(msg: &[u8]) -> Option<Question> {
    if msg.len() < HEADER_LEN || msg[2] & 0x80 != 0 || u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return None;
    }
    let mut labels = Vec::new();
    let mut at = HEADER_LEN;
    loop {
        let len = usize::from(*msg.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        // Questions do not use compression.
        if len > 63 {
            return None;
        }
        labels.push(String::from_utf8_lossy(msg.get(at..at + len)?).into_owned());
        at += len;
    }
    let qtype = u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]);
    msg.get(at + 3)?;
    Some(Question {
        name: labels.join("."),
        qtype,
        end: at + 4,
    })
}

/// A reply to `query` with no answers and `rcode`.
fn reply(query: &[u8], question: &Question, rcode: u8) -> Vec<u8> {
    let mut out = query[..question.end].to_vec();
    // QR and RA set; opcode and RD kept.
    out[2] = 0x80 | (query[2] & 0x79);
    out[3] = 0x80 | rcode;
    out[6..12].fill(0);
    out
}

/// The response code and the A and AAAA addresses of a response.
pub fn answers(msg: &[u8]) -> Option<(u8, Vec<IpAddr>)> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let rcode = msg[3] & 0x0f;
    let questions = u16::from_be_bytes([msg[4], msg[5]]);
    let count = u16::from_be_bytes([msg[6], msg[7]]);
    let mut at = HEADER_LEN;
    for _ in 0..questions {
        at = skip_name(msg, at)? + 4;
    }
    let mut ips = Vec::new();
    for _ in 0..count {
        at = skip_name(msg, at)?;
        let field = |i: usize| {
            Some(u16::from_be_bytes([
                *msg.get(at + i)?,
                *msg.get(at + i + 1)?,
            ]))
        };
        let (kind, len) = (field(0)?, usize::from(field(8)?));
        let data = msg.get(at + 10..at + 10 + len)?;
        match (kind, len) {
            (1, 4) => ips.push(IpAddr::from(<[u8; 4]>::try_from(data).ok()?)),
            (28, 16) => ips.push(IpAddr::from(<[u8; 16]>::try_from(data).ok()?)),
            _ => {}
        }
        at += 10 + len;
        if ips.len() == MAX_ANSWERS {
            break;
        }
    }
    Some((rcode, ips))
}

/// Where the name at `at` ends.
fn skip_name(msg: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *msg.get(at)?;
        if len & 0xc0 == 0xc0 {
            return Some(at + 2);
        }
        at += 1 + usize::from(len);
        if len == 0 {
            return Some(at);
        }
    }
}

pub fn type_name(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

pub fn rcode_name(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        other => format!("RCODE{other}"),
    }
}

/// Listens on `port` for UDP and TCP. The host firewall lets only sandbox
/// interfaces reach it.
pub async fn start(
    inner: Arc<Inner>,
    port: u16,
    upstream: Ipv4Addr,
) -> Result<Vec<JoinHandle<()>>> {
    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))
        .await
        .with_context(|| format!("listen for DNS on UDP port {port}"))?;
    let tcp = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
        .await
        .with_context(|| format!("listen for DNS on TCP port {port}"))?;
    let upstream = SocketAddr::from((upstream, 53));
    Ok(vec![
        tokio::spawn(serve_udp(Arc::clone(&inner), Arc::new(udp), upstream)),
        tokio::spawn(serve_tcp(inner, tcp, upstream)),
    ])
}

async fn serve_udp(inner: Arc<Inner>, socket: Arc<UdpSocket>, upstream: SocketAddr) {
    let mut buf = vec![0; MAX_MESSAGE];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(got) => got,
            Err(err) => {
                eprintln!("dns: receive: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let SocketAddr::V4(peer) = peer else { continue };
        let query = buf[..n].to_vec();
        let inner = Arc::clone(&inner);
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            let reply = answer(&inner, *peer.ip(), &query, upstream, false).await;
            if let Some(reply) = reply {
                let _ = socket.send_to(&reply, peer).await;
            }
        });
    }
}

async fn serve_tcp(inner: Arc<Inner>, listener: TcpListener, upstream: SocketAddr) {
    loop {
        match listener.accept().await {
            Ok((stream, SocketAddr::V4(peer))) => {
                let inner = Arc::clone(&inner);
                tokio::spawn(async move {
                    if let Err(err) = tcp_client(&inner, stream, *peer.ip(), upstream).await {
                        eprintln!("dns: TCP from {peer}: {err:#}");
                    }
                });
            }
            Ok(_) => {}
            Err(err) => {
                eprintln!("dns: accept: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn tcp_client(
    inner: &Inner,
    mut stream: TcpStream,
    peer: Ipv4Addr,
    upstream: SocketAddr,
) -> Result<()> {
    loop {
        let Ok(query) = timeout(TCP_IDLE, read_framed(&mut stream)).await else {
            return Ok(());
        };
        let Some(query) = query? else {
            return Ok(());
        };
        let Some(reply) = answer(inner, peer, &query, upstream, true).await else {
            return Ok(());
        };
        write_framed(&mut stream, &reply).await?;
    }
}

/// One length-prefixed message, or `None` at the end of the stream.
async fn read_framed(stream: &mut TcpStream) -> Result<Option<Vec<u8>>> {
    let mut len = [0; 2];
    match stream.read_exact(&mut len).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let mut msg = vec![0; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut msg).await?;
    Ok(Some(msg))
}

async fn write_framed(stream: &mut TcpStream, msg: &[u8]) -> Result<()> {
    let len = u16::try_from(msg.len()).context("DNS message too long")?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(msg).await?;
    Ok(())
}

/// The reply to send, if any. Queries from unknown addresses and messages
/// that are not queries get none.
async fn answer(
    inner: &Inner,
    peer: Ipv4Addr,
    query: &[u8],
    upstream: SocketAddr,
    tcp: bool,
) -> Option<Vec<u8>> {
    let started = Instant::now();
    let Some(registration) = inner.registration(peer) else {
        eprintln!("dns: from unknown address {peer}: refused");
        return None;
    };
    let question = question(query)?;
    let name = normalize_host(&question.name);
    let allowed = inner.policy.allows(name.as_deref()) && registration.allows(name.as_deref());
    let (verdict, reply) = if !allowed {
        ("deny", reply(query, &question, REFUSED))
    } else {
        let asked = if tcp {
            ask_tcp(query, upstream).await
        } else {
            ask_udp(query, upstream).await
        };
        match asked {
            Ok(reply) => ("allow", reply),
            Err(err) => {
                eprintln!("dns: {} {}: {err:#}", registration.sandbox, question.name);
                ("error", reply(query, &question, SERVFAIL))
            }
        }
    };
    report(inner, &registration, &question, verdict, &reply, started);
    Some(reply)
}

fn report(
    inner: &Inner,
    registration: &Registration,
    question: &Question,
    verdict: &'static str,
    reply: &[u8],
    started: Instant,
) {
    let (rcode, ips) = answers(reply).unwrap_or((SERVFAIL, Vec::new()));
    (inner.sink)(Activity::Dns {
        sandbox: registration.sandbox.clone(),
        tenant: registration.tenant.clone(),
        name: question.name.clone(),
        qtype: type_name(question.qtype),
        verdict,
        rcode: rcode_name(rcode),
        answers: ips,
        ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    });
}

async fn ask_udp(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.connect(upstream).await?;
    socket.send(query).await?;
    let mut buf = vec![0; MAX_MESSAGE];
    let wait = async {
        loop {
            let n = socket.recv(&mut buf).await?;
            // Another reply with a stale ID is not ours.
            if n >= 2 && buf[..2] == query[..2] {
                return anyhow::Ok(buf[..n].to_vec());
            }
        }
    };
    timeout(UPSTREAM_TIMEOUT, wait)
        .await
        .context("upstream resolver timed out")?
}

async fn ask_tcp(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let ask = async {
        let mut stream = TcpStream::connect(upstream).await?;
        write_framed(&mut stream, query).await?;
        match read_framed(&mut stream).await? {
            Some(reply) => Ok(reply),
            None => bail!("upstream resolver closed the connection"),
        }
    };
    timeout(UPSTREAM_TIMEOUT, ask)
        .await
        .context("upstream resolver timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A query for `example.com` type A with ID 0x1234 and RD set.
    fn query() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        q
    }

    #[test]
    fn reads_the_question() {
        let q = question(&query()).unwrap();
        assert_eq!((q.name.as_str(), q.qtype, q.end), ("example.com", 1, 29));
        let mut reply = query();
        reply[2] |= 0x80;
        assert_eq!(question(&reply), None);
        assert_eq!(question(&query()[..20]), None);
    }

    #[test]
    fn refuses_with_the_question_and_no_answers() {
        let q = query();
        let out = reply(&q, &question(&q).unwrap(), REFUSED);
        assert_eq!(&out[..4], &[0x12, 0x34, 0x81, 0x85]);
        assert_eq!(&out[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&out[12..], &q[12..]);
        assert_eq!(answers(&out), Some((REFUSED, Vec::new())));
    }

    #[test]
    fn reads_compressed_answers() {
        let mut r = query();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 2;
        // CNAME, then A, both named by a pointer to the question.
        r.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12]);
        r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14]);
        let (rcode, ips) = answers(&r).unwrap();
        assert_eq!(rcode, 0);
        assert_eq!(ips, vec![IpAddr::from([93, 184, 215, 14])]);
    }
}
