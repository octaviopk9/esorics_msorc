use crate::msorc::random_z_p;
use crate::msorc::random_z_star_p;
use crate::msorc::ElGamalCipherText;
use crate::msorc::MercurialSignaturesOnRandomizableCiphertexts;
use crate::msorc::MercurialSignaturesOnRandomizableCiphertextsScheme;
use blake3::Hash;
use blake3::Hasher;
use blstrs::*;
use crypto_bigint::Encoding;
use crypto_bigint::U256;
use ff::Field;
use group::Group;

pub struct MPCMSoRC {
    pub msorc: MercurialSignaturesOnRandomizableCiphertextsScheme,
}

/// The hash function outputs elements over 256 bits. However, scalars are defined
/// over Zp with p << 2^256. Therefore we need to apply a modulus to the digest to be sure that
/// we have a canonical input every time.
/// We use the crate crypto bigint : we transform the digest into a bigint, apply modulus on the
/// bigint and generate a scalar from the little endian bitwise representation of the bigint.
pub fn digest_into_scalar(value_before_modulus: Hash) -> Scalar {
    let p = U256::from_be_hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    let bigint: U256 = U256::from_be_slice(value_before_modulus.as_bytes());
    let value_mod_p: U256 = bigint.reduce(&p).unwrap();
    if U256::is_zero(&value_mod_p).unwrap_u8() == 1 {
        return Scalar::from_bytes_le(&bigint.to_le_bytes()).unwrap();
    }
    let resulting_scalar: Scalar = Scalar::from_bytes_le(&value_mod_p.to_le_bytes()).unwrap();
    resulting_scalar
}

impl MPCMSoRC {
    pub fn new() -> Self {
        MPCMSoRC {
            msorc: MercurialSignaturesOnRandomizableCiphertextsScheme::new(),
        }
    }

    pub fn msg_gen(&self) -> G1Projective {
        self.msorc.msg_gen()
    }

    pub fn key_gen(&self) -> (Scalar, G1Projective) {
        self.msorc.key_gen()
    }

    #[allow(non_snake_case, non_camel_case_types)]
    pub fn encryption(&self, ek: &G1Projective, M: &G1Projective) -> ElGamalCipherText {
        self.msorc.encryption(ek, M)
    }

    pub fn decryption(&self, dk: &Scalar, c: &ElGamalCipherText) -> G1Projective {
        self.msorc.decryption(dk, c)
    }

    pub fn randomize_ciphertext(
        &self,
        ek: &G1Projective,
        c: &ElGamalCipherText,
        r_: &Scalar,
    ) -> ElGamalCipherText {
        self.msorc.randomize_ciphertext(ek, c, r_)
    }

    #[allow(clippy::type_complexity)]
    pub fn two_party_sign_key_gen(
        &self,
    ) -> (
        [Scalar; 3],
        [Scalar; 3],
        [G2Projective; 3],
        [G2Projective; 3],
        [G2Projective; 3],
    ) {
        let (p0_sk, p0_vk) = self.msorc.sign_key_gen();

        let (p1_sk, p1_vk) = self.msorc.sign_key_gen();

        let vk = [
            self.msorc.g2 * (p0_sk[0] + p1_sk[0]),
            self.msorc.g2 * (p0_sk[1] + p1_sk[1]),
            self.msorc.g2 * (p0_sk[2] + p1_sk[2]),
        ];

        (p0_sk, p1_sk, p0_vk, p1_vk, vk)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    pub fn i_sign(
        &self,
        p0_sk: &[Scalar; 3],
        p1_sk: &[Scalar; 3],
        p0_vk: &[G2Projective; 3],
        p1_vk: &[G2Projective; 3],
        C: &ElGamalCipherText,
        ek: &G1Projective,
    ) -> MercurialSignaturesOnRandomizableCiphertexts {
        let fail_res = MercurialSignaturesOnRandomizableCiphertexts {
            Z: G1Projective::identity(),
            S: G2Projective::identity(),
            T: G1Projective::identity(),
        };

        let hasher = blake3::Hasher::new();

        let (S_1_0, S_2_0, pi_0, s_0) = self.sign_round1_p0(&hasher);
        if !pi_0 {
            println!("++++++ Proof Failed in Round 1 of P0 ++++++");
            return fail_res;
        }

        let (Z_1, S_2,T_1, pi_1, r, s_1) =
            self.sign_round1_p1(p1_sk, p1_vk, &S_1_0, &S_2_0, C, ek, &hasher);
        if !pi_1 {
            println!("++++++ Proof Failed in Round 1 of P1 ++++++");
            return fail_res;
        }

        let (T_0, Z_0, tilde_pi_0) =
            self.sign_round2_p0(p0_sk, p0_vk, &T_1, &Z_1, &s_0, C, ek, &hasher);
        if !tilde_pi_0 {
            println!("++++++ Proof Failed in Round 2 of P0 ++++++");
            return fail_res;
        }

        let (sigma, tilde_pi_1) = self.sign_round2_p1(
            &T_0, &Z_0, &S_2, &S_2_0, &s_1, &r, &hasher
        );
        if !tilde_pi_1 {
            println!("++++++ Proof Failed in Round 2 of P1 ++++++");
            return fail_res;
        }

        sigma
    }

    #[allow(non_snake_case, non_camel_case_types)]
    pub fn sign_round1_p0(
        &self,
        hasher: &Hasher,
    ) -> (
        G1Projective,
        G2Projective,
        bool,
        Scalar,
    ) {
        let s_0 = random_z_star_p(); // invisible for others

        let S_1_0 = self.msorc.g1 * s_0;
        let S_2_0 = self.msorc.g2 * s_0;

        let (A_1, hA_1, c, q_1) =
            self.zk_prover_round1_p0(&S_1_0, &S_2_0, &s_0,  hasher);
        let pi_0 = self.zk_verifier_round1_p0(
            &S_1_0, &S_2_0, &A_1, &hA_1, &c, &q_1
        );

        (S_1_0, S_2_0, pi_0, s_0)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    fn zk_prover_round1_p0(
        &self,
        S_1_0: &G1Projective,
        S_2_0: &G2Projective,
        s_0: &Scalar,
        hasher: &Hasher,
    ) -> (
        G1Projective,
        G2Projective,
        Scalar,
        Scalar,
    ) {
        let a_1 = random_z_p();

        let A_1 = self.msorc.g1 * a_1;
        let hA_1 = self.msorc.g2 * a_1;

        let mut h = hasher.clone();
        h.update(&G1Affine::from(A_1).to_compressed());
        h.update(&G2Affine::from(hA_1).to_compressed());
        h.update(&G1Affine::from(S_1_0).to_compressed());
        h.update(&G2Affine::from(S_2_0).to_compressed());
        let c = digest_into_scalar(h.finalize());

        let q_1 = a_1 - c * s_0;

        (A_1, hA_1, c, q_1)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    fn zk_verifier_round1_p0(
        &self,
        S_1_0: &G1Projective,
        S_2_0: &G2Projective,
        A_1: &G1Projective,
        hA_1: &G2Projective,
        c: &Scalar,
        q_1: &Scalar,
    ) -> bool {
        let B_1 = self.msorc.g1 * q_1 + S_1_0 * c;
        let hB_1 = self.msorc.g2 * q_1 + S_2_0 * c;

        A_1.eq(&B_1) && hA_1.eq(&hB_1)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_round1_p1(
        &self,
        p1_sk: &[Scalar; 3],
        p1_vk: &[G2Projective; 3],
        S_1_0: &G1Projective,
        S_2_0: &G2Projective,
        C: &ElGamalCipherText,
        ek: &G1Projective,
        hasher: &Hasher,
    ) -> (
        G1Projective,
        G2Projective,
        G1Projective,
        bool,
        Scalar,
        Scalar,
    ) {
        let r = random_z_p(); // invisible for others
        let s_1 = random_z_star_p(); // invisible for others

        let S_2 = S_2_0 * s_1; // use in round 2
        let Z_1 = S_1_0 * r + C.C_0 * p1_sk[0] + C.C_1 * p1_sk[1] + self.msorc.g1 * p1_sk[2];
        let T_1 = S_1_0 * r + self.msorc.g1 * p1_sk[0] + ek * p1_sk[1];

        let (A_1, A_2, A_3, A_4, A_5, c, q_1, q_2, q_3, q_4) = self.zk_prover_round1_p1(
            &T_1, &Z_1, p1_vk, S_1_0, ek, C, &r, p1_sk, hasher
        );
        let pi_1 = self.zk_verifier_round1_p1(
            &T_1, &Z_1, p1_vk, S_1_0, ek, C, &A_1, &A_2, &A_3, &A_4, &A_5, &c, &q_1, &q_2, &q_3, &q_4
        );

        (Z_1, S_2, T_1, pi_1, r, s_1)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    fn zk_prover_round1_p1(
        &self,
        T_1: &G1Projective,
        Z_1: &G1Projective,
        X_p1: &[G2Projective; 3],
        S_1_0: &G1Projective,
        ek: &G1Projective,
        C: &ElGamalCipherText,
        r: &Scalar,
        x_p1: &[Scalar; 3],
        hasher: &Hasher,
    ) -> (
        G1Projective,
        G1Projective,
        G2Projective,
        G2Projective,
        G2Projective,
        Scalar,
        Scalar,
        Scalar,
        Scalar,
        Scalar,
    ) {
        let a_1 = random_z_p();
        let a_2 = random_z_p();
        let a_3 = random_z_p();
        let a_4 = random_z_p();

        let A_1 = S_1_0 * a_1 + self.msorc.g1 * a_3 + ek * a_4;
        let A_2 = S_1_0 * a_1 + self.msorc.g1 * a_2 + C.C_0 * a_3 + C.C_1 * a_4;
        let A_3 = self.msorc.g2 * a_3;
        let A_4 = self.msorc.g2 * a_4;
        let A_5 = self.msorc.g2 * a_2;

        let mut h = hasher.clone();
        h.update(&G1Affine::from(A_1).to_compressed());
        h.update(&G1Affine::from(A_2).to_compressed());
        h.update(&G2Affine::from(A_3).to_compressed());
        h.update(&G2Affine::from(A_4).to_compressed());
        h.update(&G2Affine::from(A_5).to_compressed());
        h.update(&G1Affine::from(T_1).to_compressed());
        h.update(&G1Affine::from(Z_1).to_compressed());
        h.update(&G2Affine::from(X_p1[0]).to_compressed());
        h.update(&G2Affine::from(X_p1[1]).to_compressed());
        let c = digest_into_scalar(h.finalize());

        let q_1 = a_1 - c * r;
        let q_2 = a_2 - c * x_p1[2];
        let q_3 = a_3 - c * x_p1[0];
        let q_4 = a_4 - c * x_p1[1];

        (A_1, A_2, A_3, A_4, A_5, c, q_1, q_2, q_3, q_4)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    fn zk_verifier_round1_p1(
        &self,
        T_1: &G1Projective,
        Z_1: &G1Projective,
        X_p1: &[G2Projective; 3],
        S_1_0: &G1Projective,
        ek: &G1Projective,
        C: &ElGamalCipherText,
        A_1: &G1Projective,
        A_2: &G1Projective,
        A_3: &G2Projective,
        A_4: &G2Projective,
        A_5: &G2Projective,
        c: &Scalar,
        q_1: &Scalar,
        q_2: &Scalar,
        q_3: &Scalar,
        q_4: &Scalar,
    ) -> bool {
        let B_1 = S_1_0 * q_1 + self.msorc.g1 * q_3 + ek * q_4 + T_1 * c;
        let B_2 = S_1_0 * q_1 + self.msorc.g1 * q_2 + C.C_0 * q_3 + C.C_1 * q_4 + Z_1 * c;
        let B_3 = self.msorc.g2 * q_3 + X_p1[0] * c;
        let B_4 = self.msorc.g2 * q_4 + X_p1[1] * c;
        let B_5 = self.msorc.g2 * q_2 + X_p1[2] * c;

        A_1.eq(&B_1) && A_2.eq(&B_2) && A_3.eq(&B_3) && A_4.eq(&B_4) && A_5.eq(&B_5)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_round2_p0(
        &self,
        p0_sk: &[Scalar; 3],
        p0_vk: &[G2Projective; 3],
        T_1: &G1Projective,
        Z_1: &G1Projective,
        s_0: &Scalar,
        C: &ElGamalCipherText,
        ek: &G1Projective,
        hasher: &Hasher,
    ) -> (G1Projective, G1Projective, bool) {
        let s_0_ie = s_0.invert().unwrap(); // inverse element

        let T_0 = (T_1 + self.msorc.g1 * p0_sk[0] + ek * p0_sk[1]) * s_0_ie;
        let Z_0 = (Z_1 + C.C_0 * p0_sk[0] + C.C_1 * p0_sk[1] + self.msorc.g1 * p0_sk[2]) * s_0_ie;

        let S_1_0 = self.msorc.g1 * s_0; // we can use the same value of round 1: S_1_0

        let (A_1, A_2, A_3, A_4, A_5, A_6, c, q_1, q_2, q_3, q_4) = self.zk_prover_round2_p0(
            &T_0, &Z_0, &S_1_0, T_1, Z_1, p0_vk, ek, C, s_0, p0_sk, hasher
        );
        let tilde_pi_0 = self.zk_verifier_round2_p0(
            &T_0, &Z_0, &S_1_0, T_1, Z_1, p0_vk, ek, C, &A_1, &A_2, &A_3, &A_4, &A_5, &A_6, &c, &q_1, &q_2, &q_3, &q_4
        );

        (T_0, Z_0, tilde_pi_0)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    fn zk_prover_round2_p0(
        &self,
        T_0: &G1Projective,
        Z_0: &G1Projective,
        S_1_0: &G1Projective,
        T_1: &G1Projective,
        Z_1: &G1Projective,
        X_p0: &[G2Projective; 3],
        ek: &G1Projective,
        C: &ElGamalCipherText,
        s_0: &Scalar,
        x_p0: &[Scalar; 3],
        hasher: &Hasher,
    ) -> (
        G1Projective,
        G1Projective,
        G1Projective,
        G2Projective,
        G2Projective,
        G2Projective,
        Scalar,
        Scalar,
        Scalar,
        Scalar,
        Scalar,
    ) {
        let a_1 = random_z_p(); // s_0
        let a_2 = random_z_p(); // x_p0[0]
        let a_3 = random_z_p(); // x_p0[1]
        let a_4 = random_z_p(); // x_p0[2]

        let A_1 = T_0 * a_1 - self.msorc.g1 * a_2 - ek * a_3;
        let A_2 = Z_0 * a_1 - C.C_0 * a_2 - C.C_1 * a_3 - self.msorc.g1 * a_4;
        let A_3 = self.msorc.g1 * a_1;
        let A_4 = self.msorc.g2 * a_2;
        let A_5 = self.msorc.g2 * a_3;
        let A_6 = self.msorc.g2 * a_4;

        let mut h = hasher.clone();
        h.update(&G1Affine::from(A_1).to_compressed());
        h.update(&G1Affine::from(A_2).to_compressed());
        h.update(&G1Affine::from(A_3).to_compressed());
        h.update(&G2Affine::from(A_4).to_compressed());
        h.update(&G2Affine::from(A_5).to_compressed());
        h.update(&G2Affine::from(A_6).to_compressed());
        h.update(&G1Affine::from(T_1).to_compressed());
        h.update(&G1Affine::from(Z_1).to_compressed());
        h.update(&G1Affine::from(S_1_0).to_compressed());
        h.update(&G2Affine::from(X_p0[0]).to_compressed());
        h.update(&G2Affine::from(X_p0[1]).to_compressed());
        h.update(&G2Affine::from(X_p0[2]).to_compressed());
        let c = digest_into_scalar(h.finalize());

        let q_1 = a_1 - c * s_0;
        let q_2 = a_2 - c * x_p0[0];
        let q_3 = a_3 - c * x_p0[1];
        let q_4 = a_4 - c * x_p0[2];

        (A_1, A_2, A_3, A_4, A_5, A_6, c, q_1, q_2, q_3, q_4)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    fn zk_verifier_round2_p0(
        &self,
        T_0: &G1Projective,
        Z_0: &G1Projective,
        S_1_0: &G1Projective,
        T_1: &G1Projective,
        Z_1: &G1Projective,
        X_p0: &[G2Projective; 3],
        ek: &G1Projective,
        C: &ElGamalCipherText,
        A_1: &G1Projective,
        A_2: &G1Projective,
        A_3: &G1Projective,
        A_4: &G2Projective,
        A_5: &G2Projective,
        A_6: &G2Projective,
        c: &Scalar,
        q_1: &Scalar,
        q_2: &Scalar,
        q_3: &Scalar,
        q_4: &Scalar,
    ) -> bool {
        let B_1 = T_0 * q_1 - self.msorc.g1 * q_2 - ek * q_3 + T_1 * c;
        let B_2 = Z_0 * q_1 - C.C_0 * q_2 - C.C_1 * q_3 - self.msorc.g1 * q_4 + Z_1 * c;
        let B_3 = self.msorc.g1 * q_1 + S_1_0 * c;
        let B_4 = self.msorc.g2 * q_2 + X_p0[0] * c;
        let B_5 = self.msorc.g2 * q_3 + X_p0[1] * c;
        let B_6 = self.msorc.g2 * q_4 + X_p0[2] * c;

        A_1.eq(&B_1)
            && A_2.eq(&B_2)
            && A_3.eq(&B_3)
            && A_4.eq(&B_4)
            && A_5.eq(&B_5)
            && A_6.eq(&B_6)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_round2_p1(
        &self,
        T_0: &G1Projective,
        Z_0: &G1Projective,
        S_2: &G2Projective,
        S_2_0: &G2Projective,
        s_1: &Scalar,
        r: &Scalar,
        hasher: &Hasher,
    ) -> (MercurialSignaturesOnRandomizableCiphertexts, bool) {
        let s_1_ie = s_1.invert().unwrap();

        let T = (T_0 - self.msorc.g1 * r) * s_1_ie;
        let Z = (Z_0 - self.msorc.g1 * r) * s_1_ie;

        let (A_1, A_2, A_3, c, q_1, q_2) = self.zk_prover_round2_p1(
            &T, &Z, S_2, T_0, Z_0, S_2_0, r, s_1, hasher
        );
        let tilde_pi_1 = self.zk_verifier_round2_p1(
            &T, &Z, S_2, T_0, Z_0, S_2_0, &A_1, &A_2, &A_3, &c, &q_1, &q_2
        );

        (
            MercurialSignaturesOnRandomizableCiphertexts {
                Z,
                S: *S_2,
                T,
            },
            tilde_pi_1,
        )
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    fn zk_prover_round2_p1(
        &self,
        T: &G1Projective,
        Z: &G1Projective,
        S: &G2Projective,
        T_0: &G1Projective,
        Z_0: &G1Projective,
        S_0: &G2Projective,
        r: &Scalar,
        s_1: &Scalar,
        hasher: &Hasher,
    ) -> (
        G1Projective,
        G1Projective,
        G2Projective,
        Scalar,
        Scalar,
        Scalar,
    ) {
        let a_1 = random_z_p();
        let a_2 = random_z_p();

        let A_1 = self.msorc.g1 * a_1 + T * a_2;
        let A_2 = self.msorc.g1 * a_1 + Z * a_2;
        let A_3 = S_0 * a_2;

        let mut h = hasher.clone();
        h.update(&G1Affine::from(A_1).to_compressed());
        h.update(&G1Affine::from(A_2).to_compressed());
        h.update(&G2Affine::from(A_3).to_compressed());
        h.update(&G1Affine::from(T).to_compressed());
        h.update(&G1Affine::from(Z).to_compressed());
        h.update(&G2Affine::from(S).to_compressed());
        h.update(&G1Affine::from(T_0).to_compressed());
        h.update(&G1Affine::from(Z_0).to_compressed());
        h.update(&G2Affine::from(S_0).to_compressed());
        let c = digest_into_scalar(h.finalize());

        let q_1 = a_1 - c * r;
        let q_2 = a_2 - c * s_1;

        (A_1, A_2, A_3, c, q_1, q_2)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    fn zk_verifier_round2_p1(
        &self,
        T: &G1Projective,
        Z: &G1Projective,
        S_2: &G2Projective,
        T_0: &G1Projective,
        Z_0: &G1Projective,
        S_2_0: &G2Projective,
        A_1: &G1Projective,
        A_2: &G1Projective,
        A_3: &G2Projective,
        c: &Scalar,
        q_1: &Scalar,
        q_2: &Scalar,
    ) -> bool {
        let B_1 = self.msorc.g1 * q_1 + T * q_2 + T_0 * c;
        let B_2 = self.msorc.g1 * q_1 + Z * q_2 + Z_0 * c;
        let B_3 = S_2_0 * q_2 + S_2 * c;

        A_1.eq(&B_1) && A_2.eq(&B_2) && A_3.eq(&B_3)
    }

    pub fn convert_vk(&self, vk: &[G2Projective; 3]) -> [G2Projective; 3] {
        self.msorc.convert_vk(vk)
    }

    pub fn adapt(
        &self,
        sign: &MercurialSignaturesOnRandomizableCiphertexts,
        rho: &Scalar,
        mu: &Scalar,
    ) -> MercurialSignaturesOnRandomizableCiphertexts {
        self.msorc.change_rep(sign, rho, mu)
    }

    pub fn verify(
        &self,
        vk: &[G2Projective; 3],
        ek: &G1Projective,
        c: &ElGamalCipherText,
        sign: &MercurialSignaturesOnRandomizableCiphertexts,
    ) -> bool {
        self.msorc.verify(vk, ek, c, sign)
    }
}

impl Default for MPCMSoRC {
    fn default() -> Self {
        Self::new()
    }
}
