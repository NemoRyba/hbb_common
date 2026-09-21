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
pub struct DynTcpStream(pub(crate) Box<dyn TcpStreamTrait + Send + Sync>);

/// Which side of a key exchange this cipher belongs to. The side that GENERATES the
/// symmetric key is the initiator; the side that opens it with `Encrypt::decode` is
/// the responder. That holds for every handshake in this codebase -- rendezvous,
/// relay, and both peer-to-peer paths -- so the role needs no negotiation of its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Initiator,
    Responder,
}

/// Version byte sealed alongside the symmetric key. Its presence is what tells the
/// responder that the initiator uses per-direction nonces (SEC-14). It rides INSIDE
/// the sealed box, so an on-path attacker cannot strip it to force the old shared
/// nonce space back -- doing that would need the recipient's secret key.
pub const SESSION_KEY_V1: u8 = 1;

/// A negotiated session key: the symmetric key, which side of the handshake we are,
/// and whether the peer agreed to per-direction nonces.
#[derive(Clone)]
pub struct SessionKey {
    pub key: Key,
    pub role: Role,
    /// False only against a pre-SEC-14 peer, which seals a bare 32-byte key. Both
    /// directions then share one nonce space, exactly as before.
    pub directional: bool,
}

impl SessionKey {
    /// A key we negotiated ourselves, with per-direction nonces.
    pub fn new(key: Key, role: Role) -> Self {
        Self {
            key,
            role,
            directional: true,
        }
    }

    /// Direction bytes, as (send, receive). The initiator sends with 0, which is
    /// byte-for-byte what the old code did in BOTH directions -- so the change is
    /// confined to the responder->initiator leg, and a v1 initiator's frames stay
    /// readable by anything that got past the handshake.
    fn dirs(&self) -> (u8, u8) {
        if !self.directional {
            return (0, 0);
        }
        match self.role {
            Role::Initiator => (0, 1),
            Role::Responder => (1, 0),
        }
    }
}

/// key, send counter, receive counter, send direction, receive direction.
#[derive(Clone)]
pub struct Encrypt(Key, u64, u64, u8, u8);

pub struct FramedStream(
    pub(crate) Framed<DynTcpStream, BytesCodec>,
    pub(crate) SocketAddr,
    pub(crate) Option<Encrypt>,
    pub(crate) u64,
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
        if bytes.len() <= 1 {
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

    /// Open the symmetric key the INITIATOR sealed to us, and report whether it
    /// carried the SEC-14 version marker. A bare 32-byte key means a pre-SEC-14 peer
    /// and keeps the old shared nonce space; 33 bytes means per-direction nonces.
    /// Any other length or version is refused rather than guessed at.
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
        let directional = if symmetric_key.len() == secretbox::KEYBYTES {
            false
        } else if symmetric_key.len() == secretbox::KEYBYTES + 1 {
            let version = symmetric_key[secretbox::KEYBYTES];
            if version != SESSION_KEY_V1 {
                anyhow::bail!("Handshake failed: unknown session key version {}", version);
            }
            true
        } else {
            anyhow::bail!(
                "Handshake failed: invalid secret key length {} from peer",
                symmetric_key.len()
            );
        };
        let mut key = [0u8; secretbox::KEYBYTES];
        key[..].copy_from_slice(&symmetric_key[..secretbox::KEYBYTES]);
        Ok(SessionKey {
            key: Key(key),
            role: Role::Responder,
            directional,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn pair(directional: bool) -> (Encrypt, Encrypt) {
        let key = secretbox::gen_key();
        (
            Encrypt::new(SessionKey {
                key: key.clone(),
                role: Role::Initiator,
                directional,
            }),
            Encrypt::new(SessionKey {
                key,
                role: Role::Responder,
                directional,
            }),
        )
    }

    /// SEC-14. The bug: one shared key plus one nonce space meant BOTH ends derived
    /// the same nonce from their own counters, so frame #1 in each direction
    /// encrypted the same plaintext to the same ciphertext -- XSalsa20 keystream
    /// reuse on every connection, from the very first frame. Assert both halves:
    /// that the old shape really did collide, and that the new one does not.
    #[test]
    fn directions_do_not_share_a_nonce_space() {
        let (mut legacy_i, mut legacy_r) = pair(false);
        assert_eq!(
            legacy_i.enc(b"same plaintext"),
            legacy_r.enc(b"same plaintext"),
            "pre-SEC-14 shape: two directions, one nonce space, one key (two-time pad)"
        );

        let (mut i, mut r) = pair(true);
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
        let (mut i, mut r) = pair(true);
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

    /// Against a pre-SEC-14 peer both ends fall back to the old shared nonce space,
    /// so an un-updated peer keeps working exactly as before.
    #[test]
    fn a_legacy_pair_round_trips_both_ways() {
        let (mut i, mut r) = pair(false);
        let mut wire = BytesMut::from(&i.enc(b"hello")[..]);
        r.dec(&mut wire).expect("responder decrypts");
        assert_eq!(&wire[..], b"hello");
        let mut wire = BytesMut::from(&r.enc(b"world")[..]);
        i.dec(&mut wire).expect("initiator decrypts");
        assert_eq!(&wire[..], b"world");
    }

    /// The initiator's SEND direction is 0, which is byte-for-byte what the old code
    /// did in both directions. That is deliberate: it keeps the change confined to
    /// the responder->initiator leg.
    #[test]
    fn the_initiator_send_leg_is_unchanged_from_the_legacy_shape() {
        let key = secretbox::gen_key();
        let mut v1 = Encrypt::new(SessionKey::new(key.clone(), Role::Initiator));
        let mut legacy = Encrypt::new(SessionKey {
            key,
            role: Role::Initiator,
            directional: false,
        });
        assert_eq!(v1.enc(b"first frame"), legacy.enc(b"first frame"));
    }

    /// Mixing the modes must FAIL to decrypt rather than silently produce garbage --
    /// a half-updated fleet gets a clean error, never a corrupted stream.
    #[test]
    fn a_directional_responder_cannot_be_read_by_a_legacy_initiator() {
        let key = secretbox::gen_key();
        let mut v1_r = Encrypt::new(SessionKey::new(key.clone(), Role::Responder));
        let mut legacy_i = Encrypt::new(SessionKey {
            key,
            role: Role::Initiator,
            directional: false,
        });
        let mut wire = BytesMut::from(&v1_r.enc(b"reply")[..]);
        assert!(legacy_i.dec(&mut wire).is_err());
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
