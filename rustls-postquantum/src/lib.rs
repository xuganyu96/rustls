use rustls::crypto::aws_lc_rs::{default_provider, kx_group};
use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
};
use rustls::{Error, NamedGroup, PeerMisbehaved};

use aws_lc_rs::kem;
use aws_lc_rs::unstable::kem::{get_algorithm, AlgorithmId};

pub fn provider() -> CryptoProvider {
    let parent = default_provider();
    let mut kx_groups = vec![&X25519Kyber768Draft00 as &dyn SupportedKxGroup];
    kx_groups.extend(parent.kx_groups);

    CryptoProvider {
        kx_groups,
        ..parent
    }
}

///
#[derive(Debug)]
pub struct X25519Kyber768Draft00;

impl SupportedKxGroup for X25519Kyber768Draft00 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let x25519 = kx_group::X25519.start()?;

        let kyber = kem::DecapsulationKey::generate(kyber768_r3())
            .map_err(|_| Error::FailedToGetRandomBytes)?;

        let kyber_pub = kyber
            .encapsulation_key()
            .map_err(|_| Error::FailedToGetRandomBytes)?;

        let mut combined_pub_key = Vec::with_capacity(COMBINED_PUBKEY_LEN);
        combined_pub_key.extend_from_slice(x25519.pub_key());
        combined_pub_key.extend_from_slice(kyber_pub.key_bytes().unwrap().as_ref());

        Ok(Box::new(Active {
            x25519,
            decap_key: Box::new(kyber),
            combined_pub_key,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != COMBINED_PUBKEY_LEN {
            return Err(INVALID_KEY_SHARE);
        }

        let x25519 = kx_group::X25519.start_and_complete(&client_share[..X25519_LEN])?;
        let mut combined_secret = [0u8; 64];
        combined_secret[..X25519_LEN].copy_from_slice(x25519.secret.secret_bytes());
        let mut combined_share = [0u8; COMBINED_CIPHERTEXT_LEN];
        combined_share[..X25519_LEN].copy_from_slice(&x25519.pub_key);

        let kyber_pub = kem::EncapsulationKey::new(kyber768_r3(), &client_share[X25519_LEN..])
            .map_err(|_| INVALID_KEY_SHARE)?;

        let (kyber_share, kyber_secret) = kyber_pub
            .encapsulate()
            .map_err(|_| INVALID_KEY_SHARE)?;

        combined_share[X25519_LEN..].copy_from_slice(kyber_share.as_ref());
        combined_secret[X25519_LEN..].copy_from_slice(kyber_secret.as_ref());

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: combined_share.to_vec(),
            secret: SharedSecret::from(&combined_secret[..]),
        })
    }

    fn name(&self) -> NamedGroup {
        NAMED_GROUP
    }
}

struct Active {
    x25519: Box<dyn ActiveKeyExchange>,
    decap_key: Box<kem::DecapsulationKey<AlgorithmId>>,
    combined_pub_key: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != COMBINED_CIPHERTEXT_LEN {
            return Err(INVALID_KEY_SHARE);
        }

        let x25519_ss = self
            .x25519
            .complete(&peer_pub_key[..X25519_LEN])?;

        let mut result = [0u8; COMBINED_SHARED_SECRET_LEN];
        result[..X25519_LEN].copy_from_slice(x25519_ss.secret_bytes());

        let mut ciphertext = [0u8; KYBER_CIPHERTEXT_LEN];
        ciphertext.clone_from_slice(&peer_pub_key[X25519_LEN..]);

        let secret = self
            .decap_key
            .decapsulate(ciphertext[..].into())
            .map_err(|_| INVALID_KEY_SHARE)?;
        result[X25519_LEN..].copy_from_slice(secret.as_ref());

        Ok(SharedSecret::from(&result[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn group(&self) -> NamedGroup {
        NAMED_GROUP
    }
}

fn kyber768_r3() -> &'static kem::Algorithm<AlgorithmId> {
    get_algorithm(AlgorithmId::Kyber768_R3).expect("Kyber768_R3 not available")
}

const NAMED_GROUP: NamedGroup = NamedGroup::Unknown(0x6399);

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

const X25519_LEN: usize = 32;
const KYBER_CIPHERTEXT_LEN: usize = 1088;
const COMBINED_PUBKEY_LEN: usize = X25519_LEN + 1184;
const COMBINED_CIPHERTEXT_LEN: usize = X25519_LEN + KYBER_CIPHERTEXT_LEN;
const COMBINED_SHARED_SECRET_LEN: usize = X25519_LEN + 32;
