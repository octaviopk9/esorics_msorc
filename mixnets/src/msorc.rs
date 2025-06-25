use blstrs::*;
use crypto_bigint::U256;
use ff::Field;
use group::Group;

#[derive(Debug, Clone, Copy)]
pub struct MercurialSignaturesOnRandomizableCiphertextsScheme {
    pub _p: U256,
    pub g1: G1Projective,
    pub g2: G2Projective,
    pub rho: Scalar,
    pub mu: Scalar,
}

#[allow(non_snake_case, non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
pub struct ElGamalCipherText {
    pub C_0: G1Projective,
    pub C_1: G1Projective,
}

#[allow(non_snake_case, non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
pub struct MercurialSignaturesOnRandomizableCiphertexts {
    pub Z: G1Projective,
    pub S: G2Projective,
    pub T: G1Projective,
}

/// Computes a random number in Zp\{0} mod q in potentially variable time (insignificant probability)
/// Retry as long as it equals 0, but it has insignificant probability each time
pub fn random_z_star_p() -> Scalar {
    let rng = rand::thread_rng();
    let mut random = Scalar::random(rng);
    while !random.is_zero().unwrap_u8() == 0 {
        let rng = rand::thread_rng();
        random = Scalar::random(rng);
    }
    random
}

/// Computes a random number, zero being a possibility
#[allow(dead_code)]
pub fn random_z_p() -> Scalar {
    let rng = rand::thread_rng();
    Scalar::random(rng)
}

/// Mercurial Signatures on Randomizable Elgamal Ciphertexts Scheme
impl MercurialSignaturesOnRandomizableCiphertextsScheme {
    pub fn new() -> Self {
        MercurialSignaturesOnRandomizableCiphertextsScheme {
            _p: U256::from_be_hex(
                "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
            ),
            g1: G1Projective::generator(),
            g2: G2Projective::generator(),
            rho: random_z_star_p(),
            mu: random_z_star_p(),
        }
    }

    // ElGamal encryption scheme

    pub fn msg_gen(&self) -> G1Projective {
        let m = random_z_star_p();
        self.g1 * m
    }

    pub fn key_gen(&self) -> (Scalar, G1Projective) {
        let dk = random_z_star_p();
        let ek = self.g1 * dk;
        (dk, ek)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    pub fn encryption(&self, ek: &G1Projective, m: &G1Projective) -> ElGamalCipherText {
        /*
        let r = random_z_p();
        let C_0 = self.g1 * r;
        let C_1 = m + ek * r;
        */
        let C_0 = self.g1 * self.mu;
        let C_1 = m + ek * self.mu;
        ElGamalCipherText { C_0, C_1 }
    }

    pub fn decryption(&self, dk: &Scalar, c: &ElGamalCipherText) -> G1Projective {
        c.C_1 - c.C_0 * dk
    }

    #[allow(non_snake_case, non_camel_case_types)]
    pub fn randomize_ciphertext(
        &self,
        ek: &G1Projective,
        c: &ElGamalCipherText,
        r_prm: &Scalar,
    ) -> ElGamalCipherText {
        let C_0 = c.C_0 + self.g1 * r_prm;
        let C_1 = c.C_1 + ek * r_prm;
        ElGamalCipherText { C_0, C_1 }
    }

    // Mercurial signatures scheme

    pub fn sign_key_gen(&self) -> ([Scalar; 3], [G2Projective; 3]) {
        let sk0 = random_z_star_p();
        let sk1 = random_z_star_p();
        let sk2 = random_z_star_p();
        let vk0 = self.g2 * sk0;
        let vk1 = self.g2 * sk1;
        let vk2 = self.g2 * sk2;
        ([sk0, sk1, sk2], [vk0, vk1, vk2])
    }

    #[allow(non_snake_case, non_camel_case_types)]
    pub fn sign(
        &self,
        sk: &[Scalar; 3],
        ek: &G1Projective,
        c: &ElGamalCipherText,
    ) -> MercurialSignaturesOnRandomizableCiphertexts {
        let s = random_z_star_p();
        let s_ie = s.invert().unwrap();

        let Z = (c.C_0 * sk[0] + c.C_1 * sk[1] + self.g1 * sk[2]) * s_ie;
        let S = self.g2 * s;
        let T = (self.g1 * sk[0] + ek * sk[1]) * s_ie;

        MercurialSignaturesOnRandomizableCiphertexts {
            Z,
            S,
            T,
        }
    }

    #[allow(dead_code)]
    pub fn convert_vk(&self, vk: &[G2Projective; 3]) -> [G2Projective; 3] {
        let vk0_ = vk[0] * self.rho;
        let vk1_ = vk[1] * self.rho;
        let vk2_ = vk[2] * self.rho;
        [vk0_, vk1_, vk2_]
    }

    #[allow(dead_code)]
    pub fn convert_sk(&self, sk: &[Scalar; 3]) -> [Scalar; 3] {
        let sk0_ = sk[0] * self.rho;
        let sk1_ = sk[1] * self.rho;
        let sk2_ = sk[2] * self.rho;
        [sk0_, sk1_, sk2_]
    }

    #[allow(non_snake_case, non_camel_case_types, dead_code)]
    pub fn change_rep(
        &self,
        sign: &MercurialSignaturesOnRandomizableCiphertexts,
        rho: &Scalar,
        mu: &Scalar,
    ) -> MercurialSignaturesOnRandomizableCiphertexts {
        let s_ = random_z_star_p();
        let s_ie_ = s_.invert().unwrap();

        let Z_ = (sign.Z + sign.T * mu) * rho * s_ie_;
        let S_ = sign.S * s_;
        let T_ = sign.T * rho * s_ie_;

        MercurialSignaturesOnRandomizableCiphertexts {
            Z: Z_,
            S: S_,
            T: T_,
        }
    }

    pub fn verify(
        &self,
        vk: &[G2Projective; 3],
        ek: &G1Projective,
        c: &ElGamalCipherText,
        sign: &MercurialSignaturesOnRandomizableCiphertexts,
    ) -> bool {
        let e1 = pairing(&G1Affine::from(sign.Z), &G2Affine::from(sign.S));
        let e2_1 = pairing(&G1Affine::from(c.C_0), &G2Affine::from(vk[0]));
        let e2_2 = pairing(&G1Affine::from(c.C_1), &G2Affine::from(vk[1]));
        let e2_3 = pairing(&G1Affine::from(self.g1), &G2Affine::from(vk[2]));

        let e5 = pairing(&G1Affine::from(sign.T), &G2Affine::from(sign.S));
        let e6_1 = pairing(&G1Affine::from(self.g1), &G2Affine::from(vk[0]));
        let e6_2 = pairing(&G1Affine::from(ek), &G2Affine::from(vk[1]));

        e1 == e2_1 + e2_2 + e2_3 && 
        e5 == e6_1 + e6_2
    }
}

impl Default for MercurialSignaturesOnRandomizableCiphertextsScheme {
    fn default() -> Self {
        Self::new()
    }
}
