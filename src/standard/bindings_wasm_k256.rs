// TODO: Write the docs
#![allow(missing_docs)]

use alloc::vec::Vec;
use elliptic_curve::ff::PrimeField;
use js_sys::Uint8Array;
use rand::rngs::OsRng;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct SecretKey(k256::SecretKey);

#[wasm_bindgen]
impl SecretKey {
    /// Generates a random secret key using the default RNG.
    pub fn random() -> Self {
        Self(k256::SecretKey::random(&mut OsRng))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> SecretKey {
        let sk = k256::SecretKey::from_be_bytes(data).unwrap();
        Self(sk)
    }
}

impl SecretKey {
    pub fn inner(&self) -> &k256::SecretKey {
        &self.0
    }
}

#[wasm_bindgen]
pub struct Shamir(crate::Shamir);

#[wasm_bindgen]
impl Shamir {
    #[wasm_bindgen(constructor)]
    pub fn new(t: usize, n: usize) -> Self {
        Self(crate::Shamir { t, n })
    }

    #[wasm_bindgen(js_name = splitSecret)]
    pub fn split_secret(&self, sk: &SecretKey) -> Vec<Uint8Array> {
        let secret = crate::secp256k1::WrappedScalar(*sk.0.to_nonzero_scalar());
        let ss = self
            .0
            .split_secret::<crate::secp256k1::WrappedScalar, OsRng>(secret, &mut OsRng)
            .unwrap();
        ss.into_iter().map(|x| x.as_ref().into()).collect()
    }

    #[wasm_bindgen(js_name = combineShares)]
    pub fn combine_shares(&self, data: Vec<Uint8Array>) -> SecretKey {
        let ss: Vec<_> = data
            .into_iter()
            .map(|d| crate::Share::try_from(&d.to_vec()[..]).unwrap())
            .collect();
        let c = self
            .0
            .combine_shares::<crate::secp256k1::WrappedScalar>(&ss[..])
            .unwrap();
        let nzs = k256::NonZeroScalar::from_repr(c.to_repr()).unwrap();

        SecretKey(k256::SecretKey::from(nzs))
    }
}

impl Shamir {
    pub fn inner(&self) -> &crate::Shamir {
        &self.0
    }
}
