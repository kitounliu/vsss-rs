use vsss_rs::{Shamir, secp256k1::WrappedScalar, Share};
use elliptic_curve::ff::PrimeField;
use k256::{NonZeroScalar, SecretKey};
use rand::rngs::OsRng;

fn main() {
     let mut osrng = OsRng::default();
     let sk = SecretKey::random(&mut osrng);

     // serialisation for secret key
     let sk_bytes = sk.to_be_bytes().to_vec();
     println!("sk bytes = {:?}", sk_bytes);
     let sk_again = SecretKey::from_be_bytes(&sk_bytes).unwrap();
     assert_eq!(sk, sk_again);

     let secret = WrappedScalar(*sk.to_nonzero_scalar());
     let res = Shamir::<2, 3>::split_secret::<WrappedScalar, OsRng, 33>(secret, &mut osrng);
     assert!(res.is_ok());
     let shares = res.unwrap();

     // serialisation for shares
     let shares_bytes: Vec<_> = shares.iter().map(|s| s.as_ref().to_vec()).collect();
     let shares_again: Vec<_> = shares_bytes.iter().map(|sb| Share::try_from(&sb[..]).unwrap()).collect();
     assert_eq!(shares[..], shares_again[..]);

     // take the first and third share to recover the secret
     let shares_subset = vec![shares[0], shares[2]];
     let res = Shamir::<2, 3>::combine_shares::<WrappedScalar, 33>(&shares_subset[..]);
     assert!(res.is_ok());
     let scalar = res.unwrap();
     let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
     let sk_dup = SecretKey::from(nzs_dup);
     assert_eq!(sk_dup.to_be_bytes(), sk.to_be_bytes());
 }