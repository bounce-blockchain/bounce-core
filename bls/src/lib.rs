use std::collections::HashSet;

// Two variants of BLS signature implementations
pub mod min_pk;
pub mod min_sig;

// Different BLS schemes
pub(crate) mod basic;
pub(crate) mod message_augmentation;
pub(crate) mod proof_of_possession;

#[macro_export]
macro_rules! impl_bls_variant {
    ($variant: ident, $sig_len: expr, $pk_len: expr,
        $dst_basic: expr,
        $dst_aug: expr,
        $dst_pop: expr,
        $dst_pop_pop: expr,
    ) => {
        pub mod basic {
            $crate::impl_basic!($dst_basic);
        }
        pub mod message_augmentation {
            $crate::impl_message_augmentation!($dst_aug);
        }
        pub mod proof_of_possession {
            $crate::impl_proof_of_possession!($dst_pop, $dst_pop_pop);
        }

        use std::hash::{Hash, Hasher};

        use anyhow::{anyhow, Result};
        use blst::$variant as blst_core;
        use rand::Rng;
        use rand::{RngCore, SeedableRng};
        use rand_chacha::ChaCha20Rng;

        pub const SIG_LENGTH: usize = $sig_len;
        pub const PUBKEY_LENGTH: usize = $pk_len;
        pub const SECKEY_LENGTH: usize = 32;

        #[derive(Debug, Clone, Copy, Default)]
        pub struct PublicKey(pub(crate) blst_core::PublicKey);

        impl PublicKey {
            pub fn to_bytes(&self) -> [u8; PUBKEY_LENGTH] {
                self.0.to_bytes()
            }

            pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey> {
                let pk = blst_core::PublicKey::from_bytes(bytes).map_err(|e| anyhow!("{:?}", e))?;
                Ok(PublicKey(pk))
            }

            pub fn key_validate(&self) -> Result<()> {
                self.0.validate().map_err(|e| anyhow!("{:?}", e))
            }
        }

        impl PartialEq for PublicKey {
            fn eq(&self, other: &Self) -> bool {
                self.to_bytes() == other.to_bytes()
            }
        }

        impl Eq for PublicKey {}

        impl Hash for PublicKey {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.to_bytes().hash(state);
            }
        }

        impl serde::ser::Serialize for PublicKey {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                serializer.serialize_bytes(&self.to_bytes())
            }
        }

        impl<'de> serde::de::Deserialize<'de> for PublicKey {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let bytes = <Vec<u8>>::deserialize(deserializer)?;
                PublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
            }
        }

        #[derive(Debug, Clone, Copy, Eq, PartialEq)]
        pub struct Signature(pub(crate) blst_core::Signature);

        impl Signature {
            pub fn to_bytes(&self) -> [u8; SIG_LENGTH] {
                self.0.to_bytes()
            }

            pub fn from_bytes(bytes: &[u8]) -> Result<Signature> {
                let sig =
                    blst_core::Signature::from_bytes(bytes).map_err(|e| anyhow!("{:?}", e))?;
                Ok(Signature(sig))
            }

            pub(crate) fn core_verify(&self, pk: &PublicKey, msg: &[u8], dst: &[u8]) -> bool {
                self.0.verify(true, msg, dst, &[], &pk.0, true) == blst::BLST_ERROR::BLST_SUCCESS
            }

            pub fn aggregate(sigs: &[&Signature]) -> Result<Signature> {
                let sigs = sigs
                    .iter()
                    .map(|sig| &sig.0)
                    .collect::<Vec<&blst_core::Signature>>();
                blst::$variant::AggregateSignature::aggregate(&sigs, true).map_or_else(
                    |e| Err(anyhow!("{:?}", e)),
                    |sig| Ok(Signature(sig.to_signature())),
                )
            }

            pub(crate) fn core_aggregate_verify(
                &self,
                pks: &[&PublicKey],
                msgs: &[&[u8]],
                dst: &[u8],
            ) -> bool {
                let pks = pks
                    .iter()
                    .map(|pk| &pk.0)
                    .collect::<Vec<&blst_core::PublicKey>>();
                self.0.aggregate_verify(true, msgs, dst, &pks, true)
                    == blst::BLST_ERROR::BLST_SUCCESS
            }
        }

        impl serde::ser::Serialize for Signature {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                serializer.serialize_bytes(&self.to_bytes())
            }
        }

        impl<'de> serde::de::Deserialize<'de> for Signature {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let bytes = <Vec<u8>>::deserialize(deserializer)?;
                Signature::from_bytes(&bytes).map_err(serde::de::Error::custom)
            }
        }

        #[derive(Debug, Default)]
        #[cfg_attr(feature = "proptest", derive(Clone))]
        pub struct SecretKey(pub(crate) blst_core::SecretKey);

        impl SecretKey {
            // TODO(taegyunk): implement to_bytes with zeroize
            pub fn to_bytes(&self) -> [u8; SECKEY_LENGTH] {
                self.0.to_bytes()
            }

            pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey> {
                let sk = blst_core::SecretKey::from_bytes(bytes).map_err(|e| anyhow!("{:?}", e))?;
                Ok(SecretKey(sk))
            }

            pub fn generate() -> Self {
                let mut rng = rand::thread_rng();
                Self::generate_with_rng(&mut rng)
            }

            pub fn generate_with_rng(rng: &mut impl RngCore) -> Self {
                let ikm: [u8; SECKEY_LENGTH] = rng.gen();
                let sk = blst_core::SecretKey::key_gen(&ikm, &[])
                    .expect("Failed to generate secret key.");
                SecretKey(sk)
            }

            pub fn generate_with_seed(seed: [u8; 32]) -> Self {
                let mut rng = ChaCha20Rng::from_seed(seed);
                Self::generate_with_rng(&mut rng)
            }

            pub(crate) fn core_sign(&self, msg: &[u8], dst: &[u8]) -> Signature {
                Signature(self.0.sign(msg, dst, &[]))
            }

            pub fn sk_to_pk(&self) -> PublicKey {
                PublicKey(self.0.sk_to_pk())
            }

            pub fn key_gen(ikm: &[u8]) -> Result<SecretKey> {
                blst_core::SecretKey::key_gen(ikm, &[])
                    .map_or_else(|e| Err(anyhow!("{:?}", e)), |sk| Ok(SecretKey(sk)))
            }
        }

        #[cfg(test)]
        impl PartialEq for SecretKey {
            fn eq(&self, other: &Self) -> bool {
                self.to_bytes() == other.to_bytes()
            }
        }

        #[cfg(test)]
        impl Eq for SecretKey {}

        impl From<&SecretKey> for PublicKey {
            fn from(sk: &SecretKey) -> Self {
                PublicKey(sk.0.sk_to_pk())
            }
        }

        #[cfg(feature = "proptest")]
        use proptest::prelude::*;

        #[cfg(feature = "proptest")]
        /// Produces a uniformly random SecretKey from a seed
        pub fn uniform_secret_key_strategy() -> impl Strategy<Value = SecretKey> {
            // No shrink is necessary as we want an exact SecretKey when it fails a test.
            any::<[u8; 32]>()
                .prop_map(SecretKey::generate_with_seed)
                .no_shrink()
        }

        #[cfg(feature = "proptest")]
        impl Arbitrary for SecretKey {
            type Parameters = ();
            type Strategy = BoxedStrategy<Self>;

            fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
                uniform_secret_key_strategy().boxed()
            }
        }
    };
}

pub(crate) fn all_distinct<'a>(msgs: &'a [&'a [u8]]) -> bool {
    let mut seen: HashSet<&[u8]> = HashSet::new();
    for msg in msgs {
        if !seen.insert(msg) {
            return false;
        }
    }
    true
}

#[macro_export]
macro_rules! test_suite {
    ($variant: ident) => {
        use $crate::$variant::*;
        #[cfg(feature = "proptest")]
        use proptest::prelude::*;

        #[test]
        fn test_pk_bytes() {
            let sk = SecretKey::generate();
            let pk = PublicKey::from(&sk);
            let bytes = pk.to_bytes();
            let pk2 = PublicKey::from_bytes(&bytes).expect("Failed to parse public key bytes");
            assert_eq!(pk, pk2);

            let pk_bytes = pk.to_bytes();
            let pk3 = PublicKey::from_bytes(&pk_bytes).unwrap();
            assert_eq!(pk, pk3);
        }

        #[test]
        fn test_sk_bytes() {
            let sk = SecretKey::generate();
            let bytes = sk.to_bytes();
            let sk2 = SecretKey::from_bytes(&bytes).expect("Fafiled to parse secret key bytes");
            assert_eq!(sk, sk2);
        }

        #[cfg(feature = "proptest")]
        proptest! {
            #[test]
            fn proptest_key_serialization(secret_key in uniform_secret_key_strategy()) {
                {
                    let encoded = secret_key.to_bytes();
                    prop_assert_eq!(SECKEY_LENGTH, encoded.len());
                    let decoded = SecretKey::from_bytes(&encoded).expect("Failed to decode secret key.");
                    prop_assert_eq!(&secret_key, &decoded);
                }
                {
                    let public_key = secret_key.sk_to_pk();
                    let encoded = public_key.to_bytes();
                    prop_assert_eq!(PUBKEY_LENGTH, encoded.len());
                    let decoded = PublicKey::from_bytes(&encoded).expect("Failed to decode public key.");
                    prop_assert_eq!(&public_key, &decoded);
                }
            }
        }

        mod basic {
            use $crate::$variant::basic::*;
            test_common!();

            #[test]
            fn test_aggregate_verify_same_msg() {
                let mut rng = rand::thread_rng();
                let sk = SecretKey::key_gen(&rng.gen::<[u8; 32]>()).unwrap();
                let pk = sk.sk_to_pk();

                let sk2 = SecretKey::key_gen(&rng.gen::<[u8; 32]>()).unwrap();
                let pk2 = sk2.sk_to_pk();

                let msg = b"Hello, World!";
                let sig1 = sk.sign(msg);
                let sig2 = sk2.sign(msg);

                let signature = Signature::aggregate(&[&sig1, &sig2]).unwrap();

                assert!(!signature.aggregate_verify(&[&pk, &pk2], &[msg, msg]))
            }
        }
        mod message_augmentation {
            use $crate::$variant::message_augmentation::*;
            test_common!();

            #[test]
            fn test_aggregate_verify_same_msg() {
                let mut rng = rand::thread_rng();
                let sk = SecretKey::key_gen(&rng.gen::<[u8; 32]>()).unwrap();
                let pk = sk.sk_to_pk();

                let sk2 = SecretKey::key_gen(&rng.gen::<[u8; 32]>()).unwrap();
                let pk2 = sk2.sk_to_pk();

                let msg = b"Hello, World!";
                let sig1 = sk.sign(msg);
                let sig2 = sk2.sign(msg);

                let signature = Signature::aggregate(&[&sig1, &sig2]).unwrap();

                assert!(signature.aggregate_verify(&[&pk, &pk2], &[msg, msg]))
            }
        }

        mod proof_of_possession {
            use $crate::$variant::proof_of_possession::*;
            test_common!();


            #[test]
            fn test_pop() {
                let mut rng = rand::thread_rng();
                let sk = SecretKey::key_gen(&rng.gen::<[u8; 32]>()).unwrap();
                let pk = sk.sk_to_pk();

                let proof = sk.pop_prove();
                assert!(proof.pop_verify(&pk));
            }

            #[test]
            fn test_fast_aggregate_verify() {
                let mut rng = rand::thread_rng();
                let sk = SecretKey::key_gen(&rng.gen::<[u8; 32]>()).unwrap();
                let pk = sk.sk_to_pk();

                let sk2 = SecretKey::key_gen(&rng.gen::<[u8; 32]>()).unwrap();
                let pk2 = sk2.sk_to_pk();

                let msg = b"Hello, World!";
                let sig1 = sk.sign(msg);
                let sig2 = sk2.sign(msg);

                let signature = Signature::aggregate(&[&sig1, &sig2]).unwrap();

                assert!(signature.fast_aggregate_verify(&[&pk, &pk2], msg))
            }

            #[test]
            fn test_aggregate_verify_same_msg() {
                let mut rng = rand::thread_rng();
                let sk = SecretKey::key_gen(&rng.gen::<[u8; 32]>()).unwrap();
                let pk = sk.sk_to_pk();

                let sk2 = SecretKey::key_gen(&rng.gen::<[u8; 32]>()).unwrap();
                let pk2 = sk2.sk_to_pk();

                let msg = b"Hello, World!";
                let sig1 = sk.sign(msg);
                let sig2 = sk2.sign(msg);

                let signature = Signature::aggregate(&[&sig1, &sig2]).unwrap();

                assert!(signature.aggregate_verify(&[&pk, &pk2], &[msg, msg]))
            }
        }
    }
}

#[macro_export]
macro_rules! test_common {
    () => {
        #[cfg(feature = "proptest")]
        use proptest::prelude::*;
        use rand::Rng;

        #[test]
        fn test_sign_verify() {
            let mut rng = rand::thread_rng();
            let ikm = rng.gen::<[u8; 32]>();
            let sk = SecretKey::key_gen(&ikm).unwrap();
            let pk = sk.sk_to_pk();
            let message = b"Hello world!";
            let sig = sk.sign(message);
            assert!(sig.verify(&pk, message));
        }

        #[test]
        fn test_aggregate_verify() {
            let mut rng = rand::thread_rng();
            let sk = SecretKey::key_gen(&rng.gen::<[u8; 32]>()).unwrap();
            let pk = sk.sk_to_pk();

            let sk2 = SecretKey::key_gen(&rng.gen::<[u8; 32]>()).unwrap();
            let pk2 = sk2.sk_to_pk();

            let msg1 = b"Hello,";
            let msg2 = b"World!";
            let sig1 = sk.sign(msg1);
            let sig2 = sk2.sign(msg2);

            let signature = Signature::aggregate(&[&sig1, &sig2]).unwrap();

            assert!(signature.aggregate_verify(&[&pk, &pk2], &[msg1, msg2]))
        }

        #[test]
        fn test_sig_bytes() {
            let sk = SecretKey::generate();
            let message = b"Hello world!";
            let signature = sk.sign(message);

            let sig_bytes = signature.to_bytes();
            let sig_from_bytes = Signature::from_bytes(&sig_bytes).unwrap();
            assert_eq!(signature, sig_from_bytes);
        }

        #[cfg(feature = "proptest")]
        proptest! {
            #[test]
            fn proptest_key_gen(secret_key in any::<SecretKey>()) {
                let public_key = secret_key.sk_to_pk();
                prop_assert!(public_key.key_validate().is_ok());
            }

            #[test]
            fn proptest_sign_verify(secret_key in uniform_secret_key_strategy(), hash in any::<[u8; 32]>()) {
                let signature = secret_key.sign(&hash);
                prop_assert!(signature.verify(&secret_key.sk_to_pk(), hash.as_ref()));
            }
        }
    };
}

#[cfg(test)]
mod tests {
    mod min_sig {
        test_suite!(min_sig);
    }

    mod min_pk {
        test_suite!(min_pk);
    }
}
