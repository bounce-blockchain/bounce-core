#[macro_export]
macro_rules! impl_message_augmentation {
    ($dst: expr) => {
        pub use super::*;

        pub const DST: &[u8] = $dst;

        pub trait SecretKeyAug {
            fn sign(&self, msg: &[u8]) -> Signature;
        }

        pub trait SignatureAug {
            fn verify(&self, pk: &PublicKey, msg: &[u8]) -> bool;
            fn aggregate_verify(&self, pks: &[&PublicKey], msgs: &[&[u8]]) -> bool;
        }

        impl SecretKeyAug for SecretKey {
            fn sign(&self, msg: &[u8]) -> Signature {
                let pk = self.sk_to_pk();
                let mut pk_vec = pk.to_bytes().to_vec();
                pk_vec.extend(msg);
                self.core_sign(&pk_vec, DST)
            }
        }

        impl SignatureAug for Signature {
            fn verify(&self, pk: &PublicKey, msg: &[u8]) -> bool {
                let mut pk_with_msg = pk.to_bytes().to_vec();
                pk_with_msg.extend(msg);
                self.core_verify(pk, &pk_with_msg, DST)
            }

            fn aggregate_verify(&self, pks: &[&PublicKey], msgs: &[&[u8]]) -> bool {
                if pks.len() != msgs.len() {
                    return false;
                }
                let mut pks_with_msgs = Vec::new();

                for (pk, msg) in pks.iter().zip(msgs.iter()) {
                    let mut pk_with_msg = pk.to_bytes().to_vec();
                    pk_with_msg.extend(*msg);
                    pks_with_msgs.push(pk_with_msg);
                }

                let pks_with_msgs_refs: Vec<&[u8]> =
                    pks_with_msgs.iter().map(|v| v.as_ref()).collect::<Vec<_>>();

                self.core_aggregate_verify(pks, &pks_with_msgs_refs, DST)
            }
        }
    };
}
