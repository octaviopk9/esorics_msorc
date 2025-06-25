use blake3::Hash;
use blake3::Hasher;
use blstrs::*;
use crypto_bigint::Encoding;
use crypto_bigint::U256;
use ff::Field;
use group::Group;
use rand::seq::SliceRandom;

use crate::mpc_msorc::MPCMSoRC;
use crate::msorc::random_z_p;
use crate::msorc::random_z_star_p;
use crate::msorc::ElGamalCipherText;
use crate::msorc::MercurialSignaturesOnRandomizableCiphertexts;

#[allow(non_snake_case)]
pub struct MixNets {
    pub mpc_msorc: MPCMSoRC,
    pub crs_param: G1Projective, // Z
    // pub crs_param: G2Projective, // \hat Z
    pub w1: G1Projective, // W
    pub w2: G2Projective, // \hat W
    pub ek: G1Projective,
    pub u: usize, // number of users
    pub S: usize, // number of mix servers
}

#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct MixSign {
    pub sigma: MercurialSignaturesOnRandomizableCiphertexts, // \sigma
    pub rndmz_cipher: ElGamalCipherText,                     // C'
    pub evk: [G2Projective; 3],                              // evk
}

#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct MixSigma1 {
    pub S_0: G1Projective,
    pub hat_S_0: G2Projective, // \hat S_0
    pub U_0: G1Projective,
    pub hat_U_0: G2Projective, // \hat U_0
    pub pi_0: bool,
    pub C: ElGamalCipherText,
    pub A_g1: G1Projective,      // commitment in G1 group
    pub A_g2: Vec<G2Projective>, // commitments in G2 group
    pub c: Scalar,               // challenge
    pub z: Vec<Scalar>,
}

#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct MixSigma2 {
    pub T_1: G1Projective,
    pub Z_1: G1Projective,
    pub pi_1: bool,
    pub C_prm: ElGamalCipherText, // C'=(C_0', C_1')
    pub pi_prm: bool,             // \pi'
}

#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct MixSigma3 {
    pub T_0: G1Projective,
    pub Z_0: G1Projective,
    pub tld_pi_0: bool, // \tilde \pi_0
}

#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct MixMsg {
    pub C: ElGamalCipherText,
    pub sigma: MercurialSignaturesOnRandomizableCiphertexts,
    pub vk0: G2Projective,
    pub vk1: G2Projective,
    pub vk2: G2Projective,
}

#[derive(Debug, Clone)]
pub struct SASSign {
    pub agg_sig_1: G1Projective, // first element of SAS signature; \sigma_1
    pub agg_sig_2: G1Projective, // second element of SAS signature; \sigma_2
}

#[derive(Debug, Clone)]
pub struct NIZKProve {
    pub nizk_a0: G2Projective, // a_0
    pub nizk_a1: G2Projective, // a_1
    pub nizk_a2: G2Projective, // a_2
    pub nizk_d: G1Projective,  // d in G1 group
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

impl MixNets {
    #[allow(non_snake_case)]
    pub fn mix_setup(u: usize, S: usize) -> Self {
        let mpc_msorc = MPCMSoRC::new();
        let (_, ek) = mpc_msorc.key_gen();
        let z = random_z_p();
        let crs_param = mpc_msorc.msorc.g1 * z;
        let w = random_z_p();
        let w1 = mpc_msorc.msorc.g1 * w;
        let w2 = mpc_msorc.msorc.g2 * w;
        MixNets {
            mpc_msorc,
            crs_param,
            w1,
            w2,
            ek,
            u,
            S,
        }
    }
    pub fn msg_gen(&self) -> G1Projective {
        self.mpc_msorc.msg_gen()
    }

    #[allow(clippy::type_complexity)]
    pub fn mix_key_gen(
        &self,
    ) -> (
        Vec<Scalar>,            // ssk_j (j = 1, ..., N)
        Vec<G2Projective>,      // spk_j (j = 1, ..., N)
        Vec<[Scalar; 3]>,       // usk_i (i = 1, ..., n)
        Vec<[G2Projective; 3]>, // uvk_i (i = 1, ..., n)
        [Scalar; 3],            // ask
        [G2Projective; 3],      // avk
    ) {
        // Generate SAS signatures key for mix servers
        let mut ssk: Vec<Scalar> = Vec::with_capacity(self.S);
        let mut spk: Vec<G2Projective> = Vec::with_capacity(self.S);
        for _ in 0..self.S {
            let ssk_j = random_z_star_p();
            let spk_j = self.mpc_msorc.msorc.g2 * ssk_j;
            ssk.push(ssk_j);
            spk.push(spk_j);
        }

        // Generate MSoRC signatures key for users
        let mut usk: Vec<[Scalar; 3]> = Vec::with_capacity(self.u);
        let mut uvk: Vec<[G2Projective; 3]> = Vec::with_capacity(self.u);
        for _ in 0..self.u {
            let (usk_i, _, uvk_i, _, _) = self.mpc_msorc.two_party_sign_key_gen();
            usk.push(usk_i);
            uvk.push(uvk_i);
        }

        // Generate MSoRC signatures key for CA
        let (
            _,
            ask,
            _,
            avk,
            _, // don't use generayed verification key for MSoRC
        ) = self.mpc_msorc.two_party_sign_key_gen();

        (ssk, spk, usk, uvk, ask, avk)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    pub fn mix_sign(
        &self,
        usk_i: &[Scalar; 3],
        uvk_i: &[G2Projective; 3],
        ask: &[Scalar; 3],
        avk: &[G2Projective; 3],
        M: &G1Projective,
    ) -> MixSign {
        let fail_res = MixSign {
            sigma: MercurialSignaturesOnRandomizableCiphertexts {
                Z: G1Projective::generator(),
                S: G2Projective::generator(),
                T: G1Projective::generator(),
            },
            rndmz_cipher: ElGamalCipherText {
                C_0: G1Projective::generator(),
                C_1: G1Projective::generator(),
            },
            evk: [
                G2Projective::generator(),
                G2Projective::generator(),
                G2Projective::generator(),
            ],
        };

        // Setup the hash function
        let hasher = Hasher::new();

        let (C, pi) = self.mixsig_u_enc(M, usk_i, uvk_i, &hasher);
        if !pi {
            println!("++++++ Failed to Verify MixSig User Encryption ++++++");
            return fail_res;
        }

        let (esk_i, evk_i, C_, pi_prm) = self.mixsig_ca_rndmz(&C, &hasher);
        if !pi_prm {
            println!("++++++ Failed to Verify MixSig CA ElGamal Randomization ++++++");
            return fail_res;
        }

        let cask_i = [ask[0] + esk_i[0], ask[1] + esk_i[1], ask[2] + esk_i[2]];
        let cavk_i = [avk[0] + evk_i[0], avk[1] + evk_i[1], avk[2] + evk_i[2]];

        let sigma = self.mpc_msorc.i_sign(usk_i, &cask_i, uvk_i, &cavk_i, &C_, &self.ek);
    
        MixSign {
            sigma,
            rndmz_cipher: C_,
            evk: evk_i,
        }    
    }

    #[allow(non_snake_case, non_camel_case_types)]
    fn mixsig_u_enc(
        &self,
        M: &G1Projective,
        usk_i: &[Scalar; 3],
        uvk_i: &[G2Projective; 3],
        hasher: &Hasher,
    ) -> (
        ElGamalCipherText, // C
        bool,
    ) {
        let C = self.mpc_msorc.encryption(&self.ek, M);

        let (A_g1, A_g2, c, z_g1, z_g2) = self.mixsig_u_enc_prove(&C, usk_i, uvk_i, hasher);

        let pi = self.mixsig_u_sig_verify(&A_g1, &A_g2, &c, &z_g1, &z_g2, &C, uvk_i);

        (C, pi)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    fn mixsig_u_enc_prove(
        &self,
        C: &ElGamalCipherText,
        usk_i: &[Scalar; 3],
        uvk_i: &[G2Projective; 3],
        hasher: &Hasher,
    ) -> (
        G1Projective,
        [G2Projective; 3],
        Scalar,
        Scalar,
        [Scalar; 3],
    ) {
        let a_0 = random_z_p();
        let a_1 = random_z_p();
        let a_2 = random_z_p();
        let a_3 = random_z_p();

        let A_0 = self.mpc_msorc.msorc.g2 * a_0;
        let A_1 = self.mpc_msorc.msorc.g2 * a_1;
        let A_2 = self.mpc_msorc.msorc.g2 * a_2;
        let A_3 = self.mpc_msorc.msorc.g1 * a_3;

        let mut h = hasher.clone();
        h.update(&G2Affine::from(A_0).to_compressed());
        h.update(&G2Affine::from(A_1).to_compressed());
        h.update(&G2Affine::from(A_2).to_compressed());
        h.update(&G1Affine::from(A_3).to_compressed());
        h.update(&G1Affine::from(self.mpc_msorc.msorc.g1).to_compressed());
        h.update(&G2Affine::from(self.mpc_msorc.msorc.g2).to_compressed());
        h.update(&G1Affine::from(C.C_0).to_compressed());
        h.update(&G2Affine::from(uvk_i[0]).to_compressed());
        h.update(&G2Affine::from(uvk_i[1]).to_compressed());
        h.update(&G2Affine::from(uvk_i[2]).to_compressed());

        let c = digest_into_scalar(h.finalize());

        let z_0 = a_0 - c * usk_i[0];
        let z_1 = a_1 - c * usk_i[1];
        let z_2 = a_2 - c * usk_i[2];
        let z_3 = a_3 - c * self.mpc_msorc.msorc.mu;

        (A_3, [A_0, A_1, A_2], c, z_3, [z_0, z_1, z_2])
    }
    
    #[allow(non_snake_case, non_camel_case_types)]
    fn mixsig_u_sig_verify(
        &self,
        A_g1: &G1Projective,
        A_g2: &[G2Projective; 3],
        c: &Scalar,
        z_g1: &Scalar,
        z_g2: &[Scalar; 3],
        C: &ElGamalCipherText,
        uvk_i: &[G2Projective; 3],
    ) -> bool {
        let B_g1 = self.mpc_msorc.msorc.g1 * z_g1 + C.C_0 * c;
        let B_g2 = [
            self.mpc_msorc.msorc.g2 * z_g2[0] + uvk_i[0] * c,
            self.mpc_msorc.msorc.g2 * z_g2[1] + uvk_i[1] * c,
            self.mpc_msorc.msorc.g2 * z_g2[2] + uvk_i[2] * c,
        ];

        A_g1.eq(&B_g1) && A_g2.eq(&B_g2)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    fn mixsig_ca_rndmz(
        &self,
        C: &ElGamalCipherText,
        hasher: &Hasher,
    ) -> (
        [Scalar; 3], // esk
        [G2Projective; 3], // evk
        ElGamalCipherText, // C'
        bool, // pi
    ) {
        let (esk, evk) = self.mpc_msorc.msorc.sign_key_gen();

        let C_ = self.mpc_msorc.randomize_ciphertext(&self.ek, C, &self.mpc_msorc.msorc.mu);

        let (A_0, A_1, c, q) = self.mixsig_ca_rndmz_prove(&C, &C_, &self.mpc_msorc.msorc.mu, hasher);

        let pi = self.mixsig_ca_rndmz_verify(&C, &C_, &A_0, &A_1, &c, &q);

        (esk, evk, C_, pi)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    fn mixsig_ca_rndmz_prove(
        &self,
        C: &ElGamalCipherText,
        C_: &ElGamalCipherText,
        mu: &Scalar,
        hasher: &Hasher,
    ) -> (
        G1Projective,
        G1Projective,
        Scalar,
        Scalar,
    ) {
        let a = random_z_p();
        let A_0 = C.C_0 + self.mpc_msorc.msorc.g1 * a;
        let A_1 = C.C_1 + self.ek * a;

        let mut h = hasher.clone();
        h.update(&G1Affine::from(C.C_0).to_compressed());
        h.update(&G1Affine::from(C.C_1).to_compressed());
        h.update(&G1Affine::from(C_.C_0).to_compressed());
        h.update(&G1Affine::from(C_.C_1).to_compressed());
        h.update(&G1Affine::from(self.mpc_msorc.msorc.g1).to_compressed());
        h.update(&G1Affine::from(self.ek).to_compressed());
        h.update(&G1Affine::from(A_0).to_compressed());
        h.update(&G1Affine::from(A_1).to_compressed());
        let c = digest_into_scalar(h.finalize());

        let q = a - c * mu;

        (A_0, A_1, c, q)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    fn mixsig_ca_rndmz_verify(
        &self,
        C: &ElGamalCipherText,
        C_: &ElGamalCipherText,
        A_0: &G1Projective,
        A_1: &G1Projective,
        c: &Scalar,
        q: &Scalar,
    ) -> bool {
        let B_0 = C.C_0 + self.mpc_msorc.msorc.g1 * q + (C_.C_0 - C.C_0) * c;
        let B_1 = C.C_1 + self.ek * q + (C_.C_1 - C.C_1) * c;

        A_0.eq(&B_0) && A_1.eq(&B_1)
    }

    /// In mixnets, each of voted messages (cipher texts) are verified before mixing
    pub fn mix_init(
        &self,
        sign_list: &Vec<MixSign>,
        uvk_list: &[[G2Projective; 3]],
        avk: &[G2Projective; 3],
    ) -> bool {
        // Verify each of MSoRC signatures

        let mut seen = std::collections::HashSet::new();

        for i in 0..sign_list.len() {
            let sign = &sign_list[i];
            let uvk_i = &uvk_list[i];

            let vk = [
                uvk_i[0] + sign.evk[0] + avk[0],
                uvk_i[1] + sign.evk[1] + avk[1],
                uvk_i[2] + sign.evk[2] + avk[2],
            ];

            if !seen.insert(vk[0].to_compressed()) {
                println!("++++++ Failed to Verify Unique VKs ++++++");
                return false; // Found a duplicate
            }

            if !self
                .mpc_msorc
                .verify(&vk, &self.ek, &sign.rndmz_cipher, &sign.sigma)
            {
                println!("++++++ Failed to Verify MSoRC Signatures of User {i} ++++++");
                return false;
            }
        }

        true
    }

    fn sas_sign(
        &self,
        sk: &Scalar,
        sigma: &SASSign,
        stored_m: &[Scalar],
        stored_pk: &[G2Projective],
        m: &Scalar,
    ) -> SASSign {
        let failed_res = SASSign {
            agg_sig_1: self.mpc_msorc.msorc.g1,
            agg_sig_2: self.w1,
        };

        // If there is no stored message, then generate a new SAS signature without verification
        if stored_m.is_empty() {
            let t = random_z_star_p();
            return SASSign {
                agg_sig_1: self.mpc_msorc.msorc.g1 * t,
                agg_sig_2: (self.w1 + self.mpc_msorc.msorc.g1 * (sk * m)) * t,
            };
        }

        let mut pk_already_stored = false;
        for m_j in stored_m {
            if m_j == m {
                pk_already_stored = true;
                break;
            }
        }

        if !stored_m.is_empty() && !self.sas_verify(sigma, stored_m, stored_pk) {
            println!(
                "++++++ Failed to Verify SAS Signatures by condition: Previous Verification ++++++"
            );
            return failed_res;
        }

        if m == &Scalar::ZERO {
            println!("++++++ Failed to Verify SAS Signatures by condition: m == 0 ++++++");
            return failed_res;
        }

        if pk_already_stored {
            println!("++++++ Failed to Verify SAS Signatures by condition: Depulicated pk ++++++");
            return failed_res;
        }

        let t = random_z_star_p();

        SASSign {
            agg_sig_1: sigma.agg_sig_1 * t,
            agg_sig_2: (sigma.agg_sig_2 + sigma.agg_sig_1 * (sk * m)) * t,
        }
    }

    pub fn sas_verify(&self, sigma: &SASSign, stored_m: &[Scalar], stored_pk: &[G2Projective]) -> bool {
        let e1 = pairing(
            &G1Affine::from(sigma.agg_sig_1),
            &G2Affine::from(self.w2 + G2Projective::multi_exp(stored_pk, stored_m)),
        );
        let e2 = pairing(
            &G1Affine::from(sigma.agg_sig_2),
            &G2Affine::from(self.mpc_msorc.msorc.g2),
        );

        sigma.agg_sig_1 != G1Projective::generator() * Scalar::ZERO && e1 == e2
    }

    /// Each of Mix Server mixes the voted messages (cipher texts)
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn mix(
        &self,
        ssk_j: &Scalar,
        spk_j: &G2Projective,
        mix_msg_list: &Vec<MixMsg>, // in the paper, is represented as \{ (C_i, \sigma_i, vk_i) \}^{(j-1)}_{i \in [n]}
        sas_sign: &SASSign,         // in the paper, is represented as \sigma^{(j-1)}
        stored_sas_msg: &[Scalar],  // in the paper, is represented as \{ m_k \}_{k \in [j-1]}
        stored_spk: &[G2Projective], // in the paper, is represented as \{ spk_k \}_{k \in [j-1]}
    ) -> (
        Vec<MixMsg>, // shuffled mix messages
        NIZKProve,
        SASSign,           // \sigma^{(j)}
        Scalar,            // m_j
        G2Projective,      // spk_j
        [G2Projective; 3], // \{ vk_i \}^{(j)}_{i \in [n]}
    ) {
        let mu = random_z_star_p();
        let rho = random_z_star_p();

        let mut VK_0 = mix_msg_list[0].vk0;
        let mut VK_1 = mix_msg_list[0].vk1;
        let mut VK_2 = mix_msg_list[0].vk2;
        for msg in mix_msg_list.iter().skip(1) {
            VK_0 += msg.vk0;
            VK_1 += msg.vk1;
            VK_2 += msg.vk2;
        }
        // NIZK Prove
        // A: (VK_0, VK_1, VK_2), w: rho
        // x = A * w
        let r = random_z_p();
        let a = [VK_0 * r, VK_1 * r, VK_2 * r]; // vk is in G2 group
        let d = self.crs_param * rho + self.mpc_msorc.msorc.g1 * r; // d is in G1 group

        // Copy the voted message list
        let mut mixed_msgs = mix_msg_list.clone();

        // Randomize the verification key
        for i in 0..mix_msg_list.len() {
            mixed_msgs[i].vk0 = mix_msg_list[i].vk0 * rho;
            mixed_msgs[i].vk1 = mix_msg_list[i].vk1 * rho;
            mixed_msgs[i].vk2 = mix_msg_list[i].vk2 * rho;
        }

        // Generate concatenate proof and verification key for message
        // G2 group elements are hashed to Scalar
        let mut h2 = Hasher::new();
        h2.update(&G2Affine::from(a[0]).to_compressed());
        h2.update(&G2Affine::from(a[1]).to_compressed());
        h2.update(&G2Affine::from(a[2]).to_compressed());
        h2.update(&G1Affine::from(d).to_compressed());
        for msg in mix_msg_list {
            h2.update(&G2Affine::from(msg.vk0).to_compressed());
            h2.update(&G2Affine::from(msg.vk1).to_compressed());
            h2.update(&G2Affine::from(msg.vk2).to_compressed());
        }
        let m_j = digest_into_scalar(h2.finalize());

        // Generate the SAS Signature
        let sas_sigma_j = self.sas_sign(ssk_j, sas_sign, stored_sas_msg, stored_spk, &m_j);

        // Randomize ciphertexts
        for i in 0..mix_msg_list.len() {
            (mixed_msgs[i].C) =
                self.mpc_msorc
                    .randomize_ciphertext(&self.ek, &mix_msg_list[i].C, &mu);
        }

        // Randomize MSoRC signatures
        for i in 0..mix_msg_list.len() {
            (mixed_msgs[i].sigma) = self.mpc_msorc.adapt(&mix_msg_list[i].sigma, &rho, &mu);
        }

        // Shuffle the mix messages
        let mut rng = rand::thread_rng();
        mixed_msgs.shuffle(&mut rng);

        (
            mixed_msgs,
            NIZKProve {
                nizk_a0: a[0],
                nizk_a1: a[1],
                nizk_a2: a[2],
                nizk_d: d,
            },
            sas_sigma_j,
            m_j,
            *spk_j,
            [
                VK_0 * rho,
                VK_1 * rho,
                VK_2 * rho
            ],
        )
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn mix_verify(
        &self,
        _avk: &[G2Projective; 3],
        _ummixed_msg_list: &[MixMsg], // in the paper, is represented as \{ (C_i, \sigma_i, vk_i) \}^{(0)}_{i \in [n]}
        mixed_msg_list: &Vec<MixMsg>, // in the paper, is represented as \{ (C_i, \sigma_i, vk_i) \}^{(N)}_{i \in [n]}
        nizk_proving_list: &Vec<NIZKProve>, // in the paper, is represented as \pi^{(k)}_{k \in [N]}
        stored_vk: &[[G2Projective; 3]], // in the paper, are the original to the N-th \sum vk of the mix servers
        sas_sign: &SASSign,              // in the paper, is represented as \sigma^{(N)}
        stored_sas_m: &[Scalar],         // truely, stored_m isn't passed to verfier in the paper
        stored_spk: &[G2Projective],     // in the paper, is represented as \{ spk_k \}_{k \in [N]}
    ) -> bool {
        let mut verfiy_success = true;

        // Batch Verify the NIZK proof
        let mut delta_i: Vec<Scalar> = Vec::with_capacity(nizk_proving_list.len() * 3);
        for _ in 0..nizk_proving_list.len() * 3 {
            delta_i.push(random_z_p());
        }
        // Compute the left side of the equation
        let mut e1 = pairing(
            &G1Affine::from(nizk_proving_list[0].nizk_d),
            &G2Affine::from(stored_vk[0][0] * delta_i[0] + stored_vk[0][1] * delta_i[1] + stored_vk[0][2] * delta_i[2]),
        );
        for i in 1..nizk_proving_list.len() {
            e1 += pairing(
                &G1Affine::from(nizk_proving_list[i].nizk_d),
                &G2Affine::from(
                    stored_vk[i][0] * delta_i[i * 3] + stored_vk[i][1] * delta_i[i * 3 + 1] + stored_vk[i][2] * delta_i[i * 3 + 2],
                ),
            );
        }

        let mut concat_x: Vec<G2Projective> = Vec::with_capacity(nizk_proving_list.len() * 3);
        for vk_i in stored_vk.iter().skip(1) {
            concat_x.push(vk_i[0]);
            concat_x.push(vk_i[1]);
            concat_x.push(vk_i[2]);
        }
        let mut concat_a: Vec<G2Projective> = Vec::with_capacity(nizk_proving_list.len() * 3);
        for proof in nizk_proving_list {
            concat_a.push(proof.nizk_a0);
            concat_a.push(proof.nizk_a1);
            concat_a.push(proof.nizk_a2);
        }
        let x_to_the_delta = G2Projective::multi_exp(&concat_x, &delta_i);
        let a_to_the_delta = G2Projective::multi_exp(&concat_a, &delta_i);

        // Compute the right side of the equation
        let e2_1 = pairing(
            &G1Affine::from(self.crs_param),
            &G2Affine::from(x_to_the_delta),
        );
        let e2_2 = pairing(
            &G1Affine::from(self.mpc_msorc.msorc.g1),
            &G2Affine::from(a_to_the_delta),
        );

        if e1 != e2_1 + e2_2 {
            println!("++++++ Failed to Batch Verification of NIZK Proofs ++++++");
            verfiy_success = false;
        }

        // Verify the SAS signature
        if !self.sas_verify(sas_sign, stored_sas_m, stored_spk) {
            println!("++++++ Failed to Verify SAS Signatures ++++++");
            verfiy_success = false;
        }

        // Verify the MSoRC signatures
        for msg in mixed_msg_list {
            if !self
                .mpc_msorc
                .verify(&[msg.vk0, msg.vk1, msg.vk2], &self.ek, &msg.C, &msg.sigma)
            {
                println!("++++++ Failed to Verify MSoRC Signatures ++++++");
                verfiy_success = false;
            }
        }

        verfiy_success
    }

    /// In Mix*, using MSig.Sign
    pub fn mix_star(
        &self,
        msk_i: &Scalar,
        mpk_i: &G2Projective,
        mpk: &[G2Projective],
        eta: &Scalar,
    ) -> (G2Projective, Scalar) {
        let mut h1 = Hasher::new();
        h1.update(&G2Affine::from(mpk_i).to_compressed());
        for mpk_j in mpk {
            h1.update(&G2Affine::from(mpk_j).to_compressed());
        }
        let a_i = digest_into_scalar(h1.finalize());

        ((self.mpc_msorc.msorc.g2 * eta) * msk_i, a_i)
    }

    // In MixVerify*, using MSig.Verify
    // This is corresponding to the signatuires generated by Mix*
    // If we use this function, we don't need to use the function MixVerify
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn mix_verify_star(
        &self,
        avk: &G2Projective,
        _ummixed_msg_list: &[MixMsg],
        mixed_msg_list: &[MixMsg],
        proof: &NIZKProve,
        A: &[G2Projective; 3],
        x: &[G2Projective; 3],
        eta: &Scalar,
        msig: &G2Projective,
    ) -> bool {
        let mut verify_success = true;

        // Verify the NIZK proof
        let e1 = pairing(&G1Affine::from(proof.nizk_d), &G2Affine::from(A[0] + A[1] + A[2]));
        let e2_1 = pairing(
            &G1Affine::from(self.crs_param),
            &G2Affine::from(x[0] + x[1] + x[2]),
        );
        let e2_2 = pairing(
            &G1Affine::from(self.mpc_msorc.msorc.g1),
            &G2Affine::from(proof.nizk_a0 + proof.nizk_a1 + proof.nizk_a2),
        );
        if e1 != e2_1 + e2_2 {
            println!("++++++ Failed to Verify NIZK Proofs ++++++");
            verify_success = false;
        }

        // Verify the MSig
        let e1 = pairing(
            &G1Affine::from(self.mpc_msorc.msorc.g1),
            &G2Affine::from(msig),
        );
        let e2 = pairing(
            &G1Affine::from(self.mpc_msorc.msorc.g1 * eta),
            &G2Affine::from(avk),
        );
        if e1 != e2 {
            println!("++++++ Failed to Verify MSig ++++++");
            verify_success = false;
        }

        // Verify the MSoRC signatures
        for msg in mixed_msg_list {
            if !self
                .mpc_msorc
                .verify(&[msg.vk0, msg.vk1, msg.vk2], &self.ek, &msg.C, &msg.sigma)
            {
                println!("++++++ Failed to Verify MSoRC Signatures ++++++");
                verify_success = false;
            }
        }

        verify_success
    }
}
