use crate::{bail, bytes_codec::BytesCodec, ResultType, config::Socks5Server, proxy::Proxy};
use anyhow::Context as AnyhowCtx;
use bytes::{BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use protobuf::Message;
use sodiumoxide::crypto::{
    box_,
    secretbox::{self, Key, Nonce},
};
use std::{
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{lookup_host, TcpListener, TcpSocket, ToSocketAddrs},
};
use tokio_socks::IntoTargetAddr;
use tokio_util::codec::Framed;

pub trait TcpStreamTrait: AsyncRead + AsyncWrite + Unpin {}
pub struct DynTcpStream(pub Box<dyn TcpStreamTrait + Send + Sync>);

/// Which side of a key exchange this cipher belongs to. The side that GENERATES the
/// symmetric key is the initiator; the side that opens it with `Encrypt::decode` is
/// the responder. That holds for every handshake in this codebase -- rendezvous,
/// relay, and both peer-to-peer paths -- so the role needs no negotiation of its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Initiator,
    Responder,
}

/// Version byte sealed alongside the symmetric key, and the only shape accepted.
/// It rides INSIDE the sealed box, so an on-path attacker cannot strip or rewrite
/// it -- that would need the recipient's secret key.
pub const SESSION_KEY_V1: u8 = 1;

/// A negotiated session key: the symmetric key and which side of the handshake we
/// are. Per-direction nonces are unconditional; there is no mode in which the two
/// directions share a nonce space.
///
/// Deliberately NOT `Debug`: it holds key material, and a derived impl would print
/// it into any `{:?}` that happens to include it.
#[derive(Clone)]
pub struct SessionKey {
    pub key: Key,
    pub role: Role,
}

impl SessionKey {
    pub fn new(key: Key, role: Role) -> Self {
        Self { key, role }
    }

    /// Direction bytes, as (send, receive).
    fn dirs(&self) -> (u8, u8) {
        match self.role {
            Role::Initiator => (0, 1),
            Role::Responder => (1, 0),
        }
    }
}

/// key, send counter, receive counter, send direction, receive direction.
#[derive(Clone)]
pub struct Encrypt(pub Key, pub u64, pub u64, pub u8, pub u8);

pub struct FramedStream(
    pub Framed<DynTcpStream, BytesCodec>,
    pub SocketAddr,
    pub Option<Encrypt>,
    pub u64,
);

impl Deref for FramedStream {
    type Target = Framed<DynTcpStream, BytesCodec>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FramedStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for DynTcpStream {
    type Target = Box<dyn TcpStreamTrait + Send + Sync>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DynTcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub(crate) fn new_socket(addr: std::net::SocketAddr, reuse: bool) -> Result<TcpSocket, std::io::Error> {
    let socket = match addr {
        std::net::SocketAddr::V4(..) => TcpSocket::new_v4()?,
        std::net::SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };
    if reuse {
        // windows has no reuse_port, but its reuse_address
        // almost equals to unix's reuse_port + reuse_address,
        // though may introduce nondeterministic behavior
        // illumos has no support for SO_REUSEPORT
        #[cfg(all(unix, not(target_os = "illumos")))]
        socket.set_reuseport(true).ok();
        socket.set_reuseaddr(true).ok();
    }
    socket.bind(addr)?;
    Ok(socket)
}

impl FramedStream {
    pub async fn new<T: ToSocketAddrs + std::fmt::Display>(
        remote_addr: T,
        local_addr: Option<SocketAddr>,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        for remote_addr in lookup_host(&remote_addr).await? {
            let local = if let Some(addr) = local_addr {
                addr
            } else {
                crate::config::Config::get_any_listen_addr(remote_addr.is_ipv4())
            };
            if let Ok(socket) = new_socket(local, true) {
                if let Ok(Ok(stream)) =
                    super::timeout(ms_timeout, socket.connect(remote_addr)).await
                {
                    stream.set_nodelay(true).ok();
                    let addr = stream.local_addr()?;
                    return Ok(Self(
                        Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::new()),
                        addr,
                        None,
                        0,
                    ));
                }
            }
        }
        bail!(format!("Failed to connect to {remote_addr}"));
    }

    pub async fn connect<'t, T>(
        target: T,
        local_addr: Option<SocketAddr>,
        proxy_conf: &Socks5Server,
        ms_timeout: u64,
    ) -> ResultType<Self>
    where
        T: IntoTargetAddr<'t>,
    {
        let proxy = Proxy::from_conf(proxy_conf, Some(ms_timeout))?;
        proxy.connect::<T>(target, local_addr).await
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.1
    }

    pub fn set_send_timeout(&mut self, ms: u64) {
        self.3 = ms;
    }

    pub fn from(stream: impl TcpStreamTrait + Send + Sync + 'static, addr: SocketAddr) -> Self {
        Self(
            Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::new()),
            addr,
            None,
            0,
        )
    }

    pub fn set_raw(&mut self) {
        self.0.codec_mut().set_raw();
        self.2 = None;
    }

    /// Drop the session cipher but KEEP the current codec framing.
    ///
    /// `set_raw()` does both, which is wrong for the relay: hbbr encrypts only the
    /// RequestRelay control frame and must then pass the relayed payload through
    /// untouched (that payload is already end-to-end encrypted between the two
    /// peers, so re-encrypting it would be pure cost). Switching the codec to raw
    /// at that point would also desync framing when the two halves of a relayed
    /// pair disagree about raw mode.
    pub fn clear_key(&mut self) {
        self.2 = None;
    }

    pub fn is_secured(&self) -> bool {
        self.2.is_some()
    }

    #[inline]
    pub async fn send(&mut self, msg: &impl Message) -> ResultType<()> {
        self.send_raw(msg.write_to_bytes()?).await
    }

    #[inline]
    pub async fn send_raw(&mut self, msg: Vec<u8>) -> ResultType<()> {
        let mut msg = msg;
        if let Some(key) = self.2.as_mut() {
            msg = key.enc(&msg);
        }
        self.send_bytes(bytes::Bytes::from(msg)).await?;
        Ok(())
    }

    #[inline]
    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        if self.3 > 0 {
            super::timeout(self.3, self.0.send(bytes)).await??;
        } else {
            self.0.send(bytes).await?;
        }
        Ok(())
    }

    #[inline]
    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        let mut res = self.0.next().await;
        if let Some(Ok(bytes)) = res.as_mut() {
            if let Some(key) = self.2.as_mut() {
                if let Err(err) = key.dec(bytes) {
                    return Some(Err(err));
                }
            }
        }
        res
    }

    #[inline]
    pub async fn next_timeout(&mut self, ms: u64) -> Option<Result<BytesMut, Error>> {
        if let Ok(res) = super::timeout(ms, self.next()).await {
            res
        } else {
            None
        }
    }

    pub fn set_key(&mut self, session: SessionKey) {
        self.2 = Some(Encrypt::new(session));
    }

    fn get_nonce(seqnum: u64, dir: u8) -> Nonce {
        let mut nonce = Nonce([0u8; secretbox::NONCEBYTES]);
        nonce.0[..std::mem::size_of_val(&seqnum)].copy_from_slice(&seqnum.to_le_bytes());
        // SEC-14: this byte is what separates the two directions' nonce spaces.
        // Without it both ends derive the SAME nonce from their own counters, and
        // with one shared key frame #1 in each direction reuses the XSalsa20
        // keystream -- a two-time pad on every connection, from the first frame.
        nonce.0[std::mem::size_of_val(&seqnum)] = dir;
        nonce
    }
}

const DEFAULT_BACKLOG: u32 = 128;

pub async fn new_listener<T: ToSocketAddrs>(addr: T, reuse: bool) -> ResultType<TcpListener> {
    if !reuse {
        Ok(TcpListener::bind(addr).await?)
    } else {
        let addr = lookup_host(&addr)
            .await?
            .next()
            .context("could not resolve to any address")?;
        new_socket(addr, true)?
            .listen(DEFAULT_BACKLOG)
            .map_err(anyhow::Error::msg)
    }
}

pub async fn listen_any(port: u16) -> ResultType<TcpListener> {
    if let Ok(mut socket) = TcpSocket::new_v6() {
        #[cfg(unix)]
        {
            // illumos has no support for SO_REUSEPORT
            #[cfg(not(target_os = "illumos"))]
            socket.set_reuseport(true).ok();
            socket.set_reuseaddr(true).ok();
            use std::os::unix::io::{FromRawFd, IntoRawFd};
            let raw_fd = socket.into_raw_fd();
            let sock2 = unsafe { socket2::Socket::from_raw_fd(raw_fd) };
            sock2.set_only_v6(false).ok();
            socket = unsafe { TcpSocket::from_raw_fd(sock2.into_raw_fd()) };
        }
        #[cfg(windows)]
        {
            use std::os::windows::prelude::{FromRawSocket, IntoRawSocket};
            let raw_socket = socket.into_raw_socket();
            let sock2 = unsafe { socket2::Socket::from_raw_socket(raw_socket) };
            sock2.set_only_v6(false).ok();
            socket = unsafe { TcpSocket::from_raw_socket(sock2.into_raw_socket()) };
        }
        if socket
            .bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port))
            .is_ok()
        {
            if let Ok(l) = socket.listen(DEFAULT_BACKLOG) {
                return Ok(l);
            }
        }
    }
    Ok(new_socket(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        true,
    )?
    .listen(DEFAULT_BACKLOG)?)
}

impl Unpin for DynTcpStream {}

impl AsyncRead for DynTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }
}

impl AsyncWrite for DynTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}

impl<R: AsyncRead + AsyncWrite + Unpin> TcpStreamTrait for R {}

impl Encrypt {
    pub fn new(session: SessionKey) -> Self {
        let (send_dir, recv_dir) = session.dirs();
        Self(session.key, 0, 0, send_dir, recv_dir)
    }

    pub fn dec(&mut self, bytes: &mut BytesMut) -> Result<(), Error> {
        // Only the EMPTY frame is exempt: it is the keep-alive both ends send raw
        // with send_bytes(Bytes::new()) and it carries nothing. Every sealed frame
        // is at least a 16-byte MAC, so anything non-empty must authenticate; a
        // 1-byte frame used to slip through here unauthenticated.
        if bytes.is_empty() {
            return Ok(());
        }
        self.2 += 1;
        let nonce = FramedStream::get_nonce(self.2, self.4);
        match secretbox::open(bytes, &nonce, &self.0) {
            Ok(res) => {
                bytes.clear();
                bytes.put_slice(&res);
                Ok(())
            }
            Err(()) => Err(Error::new(ErrorKind::Other, "decryption error")),
        }
    }

    pub fn enc(&mut self, data: &[u8]) -> Vec<u8> {
        self.1 += 1;
        let nonce = FramedStream::get_nonce(self.1, self.3);
        secretbox::seal(&data, &nonce, &self.0)
    }

    /// Open the symmetric key the INITIATOR sealed to us. It must be
    /// `key || SESSION_KEY_V1`; a bare 32-byte key is the pre-SEC-14 shape, in which
    /// both directions share one nonce space, and is refused outright rather than
    /// accepted as a fallback. There is no fleet that needs it, so there is no reason
    /// to keep a code path that silently reinstates a two-time pad.
    pub fn decode(
        symmetric_data: &[u8],
        their_pk_b: &[u8],
        our_sk_b: &box_::SecretKey,
    ) -> ResultType<SessionKey> {
        if their_pk_b.len() != box_::PUBLICKEYBYTES {
            anyhow::bail!("Handshake failed: pk length {}", their_pk_b.len());
        }
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let mut pk_ = [0u8; box_::PUBLICKEYBYTES];
        pk_[..].copy_from_slice(their_pk_b);
        let their_pk_b = box_::PublicKey(pk_);
        let symmetric_key = box_::open(symmetric_data, &nonce, &their_pk_b, &our_sk_b)
            .map_err(|_| anyhow::anyhow!("Handshake failed: box decryption failure"))?;
        if symmetric_key.len() == secretbox::KEYBYTES {
            anyhow::bail!(
                "Handshake failed: peer sealed a pre-SEC-14 session key (no version byte); \
                 that shape shares one nonce space between both directions and is refused"
            );
        }
        if symmetric_key.len() != secretbox::KEYBYTES + 1 {
            anyhow::bail!(
                "Handshake failed: invalid secret key length {} from peer",
                symmetric_key.len()
            );
        }
        let version = symmetric_key[secretbox::KEYBYTES];
        if version != SESSION_KEY_V1 {
            anyhow::bail!("Handshake failed: unknown session key version {}", version);
        }
        let mut key = [0u8; secretbox::KEYBYTES];
        key[..].copy_from_slice(&symmetric_key[..secretbox::KEYBYTES]);
        Ok(SessionKey {
            key: Key(key),
            role: Role::Responder,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use sodiumoxide::crypto::box_;

    fn pair() -> (Encrypt, Encrypt) {
        let key = secretbox::gen_key();
        (
            Encrypt::new(SessionKey::new(key.clone(), Role::Initiator)),
            Encrypt::new(SessionKey::new(key, Role::Responder)),
        )
    }

    /// The pre-SEC-14 shape: one key, one nonce space, both directions. No longer
    /// reachable through any public constructor -- built here only so the assertion
    /// that it WAS broken stays in the suite.
    fn legacy_pair() -> (Encrypt, Encrypt) {
        let key = secretbox::gen_key();
        (
            Encrypt(key.clone(), 0, 0, 0, 0),
            Encrypt(key, 0, 0, 0, 0),
        )
    }

    /// SEC-14. The bug: one shared key plus one nonce space meant BOTH ends derived
    /// the same nonce from their own counters, so frame #1 in each direction
    /// encrypted the same plaintext to the same ciphertext -- XSalsa20 keystream
    /// reuse on every connection, from the very first frame. Assert both halves:
    /// that the old shape really did collide, and that the new one does not.
    /// A 1-byte frame used to be passed through undecrypted. Only the empty
    /// keep-alive may skip authentication now (a decrypt error ends the
    /// connection, so the rejected frame's counter step does not matter).
    #[test]
    fn only_the_empty_frame_skips_authentication() {
        let (mut i, mut r) = pair();
        let mut empty = BytesMut::new();
        assert!(r.dec(&mut empty).is_ok());
        assert!(empty.is_empty());
        let mut one = BytesMut::from(&b"\x08"[..]);
        assert!(r.dec(&mut one).is_err(), "unauthenticated 1-byte frame accepted");
        let (mut i, mut r) = pair();
        let mut sealed = BytesMut::from(&i.enc(b"x")[..]);
        assert!(r.dec(&mut sealed).is_ok());
        assert_eq!(&sealed[..], b"x");
    }

    #[test]
    fn directions_do_not_share_a_nonce_space() {
        let (mut legacy_i, mut legacy_r) = legacy_pair();
        assert_eq!(
            legacy_i.enc(b"same plaintext"),
            legacy_r.enc(b"same plaintext"),
            "pre-SEC-14 shape: two directions, one nonce space, one key (two-time pad)"
        );

        let (mut i, mut r) = pair();
        assert_ne!(
            i.enc(b"same plaintext"),
            r.enc(b"same plaintext"),
            "SEC-14: the two directions must never reuse a nonce under one key"
        );
    }

    /// Both directions must still round-trip -- a nonce split that breaks decryption
    /// would be caught here rather than by a silent stall on a real connection.
    #[test]
    fn a_directional_pair_round_trips_both_ways() {
        let (mut i, mut r) = pair();
        for n in 0..4u8 {
            let msg = [b'i', n];
            let mut wire = BytesMut::from(&i.enc(&msg)[..]);
            r.dec(&mut wire).expect("responder decrypts");
            assert_eq!(&wire[..], &msg[..]);

            let msg = [b'r', n];
            let mut wire = BytesMut::from(&r.enc(&msg)[..]);
            i.dec(&mut wire).expect("initiator decrypts");
            assert_eq!(&wire[..], &msg[..]);
        }
    }

    /// A pre-SEC-14 peer seals a bare 32-byte key. That is refused at the handshake,
    /// so there is no path back to the shared nonce space -- not by an on-path
    /// attacker, and not by an un-updated peer either.
    #[test]
    fn a_pre_sec14_session_key_is_refused() {
        // The initiator (them) seals to the responder's public key with its own
        // secret; the responder opens with (their_pk, our_sk). Getting that pair the
        // wrong way round fails as a box error, not as a version error, which is why
        // the assertions below check the message and not just is_err().
        let (their_pk, their_sk) = box_::gen_keypair();
        let (our_pk, our_sk) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let seal = |payload: &[u8]| box_::seal(payload, &nonce, &our_pk, &their_sk);

        // 32 bytes: the old shape.
        let legacy = seal(&key.0);
        let err = match Encrypt::decode(&legacy, &their_pk.0, &our_sk) {
            Ok(_) => panic!("a pre-SEC-14 session key must not be accepted"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("pre-SEC-14"), "{}", err);

        // 33 bytes with the right version: accepted.
        let mut ok_payload = key.0.to_vec();
        ok_payload.push(SESSION_KEY_V1);
        let good = seal(&ok_payload);
        let session = Encrypt::decode(&good, &their_pk.0, &our_sk).expect("v1 opens");
        assert_eq!(session.key, key);
        assert_eq!(session.role, Role::Responder);

        // 33 bytes with any other version: refused, so a future v2 is never misread.
        let mut v2_payload = key.0.to_vec();
        v2_payload.push(SESSION_KEY_V1 + 1);
        let v2 = seal(&v2_payload);
        let v2_err = match Encrypt::decode(&v2, &their_pk.0, &our_sk) {
            Ok(_) => panic!("an unknown session key version must not be accepted"),
            Err(e) => e.to_string(),
        };
        assert!(v2_err.contains("unknown session key version"), "{}", v2_err);
    }

    /// The direction byte sits just past the counter, so it can never collide with a
    /// sequence number however far the counter runs.
    #[test]
    fn the_direction_byte_sits_past_the_counter() {
        let a = FramedStream::get_nonce(u64::MAX, 0);
        let b = FramedStream::get_nonce(u64::MAX, 1);
        assert_eq!(a.0[..8], b.0[..8]);
        assert_eq!(a.0[8], 0);
        assert_eq!(b.0[8], 1);
        assert_ne!(a.0, b.0);
    }
}
