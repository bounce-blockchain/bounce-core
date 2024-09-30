use bls::min_pk::proof_of_possession::*;

// Test from
// https://github.com/status-im/nim-blscurve/blob/1d428420076a230e8a46346edbc084320afdad9d/tests/eth2_vectors.nim#L33
const KNWON_SECRET_KEYS: &[&str] = &[
    "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
    "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
    "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
];

const KNOWN_PUBLIC_KEYS: &[&str] = &[
        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
    ];

const KNOWN_PROOFS:  &[&str] = &[
        "b803eb0ed93ea10224a73b6b9c725796be9f5fefd215ef7a5b97234cc956cf6870db6127b7e4d824ec62276078e787db05584ce1adbf076bc0808ca0f15b73d59060254b25393d95dfc7abe3cda566842aaedf50bbb062aae1bbb6ef3b1f77e1",
        "88bb31b27eae23038e14f9d9d1b628a39f5881b5278c3c6f0249f81ba0deb1f68aa5f8847854d6554051aa810fdf1cdb02df4af7a5647b1aa4afb60ec6d446ee17af24a8a50876ffdaf9bf475038ec5f8ebeda1c1c6a3220293e23b13a9a5d26",
        "88873ea58f5017a33facc9bf04efaf5e2f34f7bc9ce564d0481dd469326c04ef43552f50e99de8a13315dcd37a4fb9ef036d1a54e5febf5d20b6aa488f3e3c917e6a96ce6461f609ec7e0a1fd8950380922e46c3654fa7542436603f833462da",
    ];

#[test]
fn pop_prove_verify() {
    for i in 0..KNWON_SECRET_KEYS.len() {
        let sk = SecretKey::from_bytes(&hex::decode(KNWON_SECRET_KEYS[i]).unwrap()).unwrap();
        let pk = PublicKey::from_bytes(&hex::decode(KNOWN_PUBLIC_KEYS[i]).unwrap()).unwrap();
        let proof = Signature::from_bytes(&hex::decode(KNOWN_PROOFS[i]).unwrap()).unwrap();

        let pk2 = PublicKey::from(&sk);
        assert_eq!(pk, pk2);

        let proof2 = sk.pop_prove();
        assert_eq!(proof, proof2);

        assert!(proof.pop_verify(&pk));

        let wrong_pk = PublicKey::from_bytes(
            &hex::decode(KNOWN_PUBLIC_KEYS[(i + 1) % KNWON_SECRET_KEYS.len()]).unwrap(),
        )
        .unwrap();
        assert!(!proof.pop_verify(&wrong_pk));
    }
}
