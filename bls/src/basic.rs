#[macro_export]
macro_rules! impl_basic {
    ($dst: expr) => {
        use $crate::all_distinct;

        pub use super::*;

        pub const DST: &[u8] = $dst;

        pub trait SecretKeyBasic {
            fn sign(&self, msg: &[u8]) -> Signature;
        }

        pub trait SignatureBasic {
            fn verify(&self, pk: &PublicKey, msg: &[u8]) -> bool;
            fn aggregate_verify(&self, pks: &[&PublicKey], msgs: &[&[u8]]) -> bool;
        }

        impl SecretKeyBasic for SecretKey {
            fn sign(&self, msg: &[u8]) -> Signature {
                self.core_sign(msg, DST)
            }
        }

        impl SignatureBasic for Signature {
            fn verify(&self, pk: &PublicKey, msg: &[u8]) -> bool {
                self.core_verify(pk, msg, DST)
            }

            fn aggregate_verify(&self, pks: &[&PublicKey], msgs: &[&[u8]]) -> bool {
                if !all_distinct(msgs) {
                    return false;
                }
                self.core_aggregate_verify(pks, msgs, DST)
            }
        }
    };
}
