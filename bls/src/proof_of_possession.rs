#[macro_export]
macro_rules! impl_proof_of_possession {
    ($dst: expr, $dst_pop: expr) => {
        pub use super::*;

        pub const DST: &[u8] = $dst;
        pub const DST_POP: &[u8] = $dst_pop;

        pub trait SecretKeyPop {
            fn sign(&self, msg: &[u8]) -> Signature;
            fn pop_prove(&self) -> Signature;
        }

        pub trait SignaturePop {
            fn verify(&self, pk: &PublicKey, msg: &[u8]) -> bool;
            fn aggregate_verify(&self, pks: &[&PublicKey], msgs: &[&[u8]]) -> bool;
            fn pop_verify(&self, pk: &PublicKey) -> bool;
            fn fast_aggregate_verify(&self, pks: &[&PublicKey], msg: &[u8]) -> bool;
        }

        impl SecretKeyPop for SecretKey {
            fn sign(&self, msg: &[u8]) -> Signature {
                self.core_sign(msg, DST)
            }

            fn pop_prove(&self) -> Signature {
                let pk = self.sk_to_pk();
                let pk_bytes = pk.to_bytes();
                self.core_sign(&pk_bytes, DST_POP)
            }
        }

        impl SignaturePop for Signature {
            fn verify(&self, pk: &PublicKey, msg: &[u8]) -> bool {
                self.core_verify(pk, msg, DST)
            }

            fn aggregate_verify(&self, pks: &[&PublicKey], msgs: &[&[u8]]) -> bool {
                self.core_aggregate_verify(pks, msgs, DST)
            }

            fn pop_verify(&self, pk: &PublicKey) -> bool {
                let pk_bytes = pk.to_bytes();
                self.core_verify(pk, &pk_bytes, DST_POP)
            }

            fn fast_aggregate_verify(&self, pks: &[&PublicKey], msg: &[u8]) -> bool {
                let pks: Vec<&blst_core::PublicKey> =
                    pks.iter().map(|pk| &pk.0).collect::<Vec<_>>();
                self.0.fast_aggregate_verify(true, msg, DST, &pks) == blst::BLST_ERROR::BLST_SUCCESS
            }
        }
    };
}
