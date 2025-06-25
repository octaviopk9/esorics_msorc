mod msorc;

use blake3::Hasher;
use blstrs::*;
use mixnets::MixSign;
use mpc_msorc::digest_into_scalar;
use msorc::random_z_p;
use msorc::MercurialSignaturesOnRandomizableCiphertextsScheme;

mod mpc_msorc;
use mpc_msorc::MPCMSoRC;

mod mixnets;
use mixnets::MixNets;

use crate::mixnets::MixMsg;
use crate::mixnets::NIZKProve;
use crate::mixnets::SASSign;

#[allow(non_snake_case, non_camel_case_types)]
fn test_msorc() {
    let msorc = MercurialSignaturesOnRandomizableCiphertextsScheme::new();

    let M = msorc.msg_gen();
    let (dk, ek) = msorc.key_gen();
    let c = msorc.encryption(&ek, &M);
    let r_prm = random_z_p();
    let c_ = msorc.randomize_ciphertext(&ek, &c, &r_prm);
    if M == msorc.decryption(&dk, &c_) {
        println!("====== Randomizable Ciphertexts are correctly Decrypted ======");
    } else {
        println!("++++++ Something went wrong in Randomizable ElGamal Scheme ++++++");
    }

    let (sk, vk) = msorc.sign_key_gen();
    let sig = msorc.sign(&sk, &ek, &c);
    // let vk_ = vk.clone();
    if msorc.verify(&vk, &ek, &c, &sig) {
        println!("====== Mercurial Signatures are correctly Verified ======");
    } else {
        println!("++++++ Something went wrong in Mercurial Signatures Scheme ++++++");
    }

    let vk_ = msorc.convert_vk(&vk);
    let c_ = msorc.randomize_ciphertext(&ek, &c, &msorc.mu);
    let sig_ = msorc.change_rep(&sig, &msorc.rho, &msorc.mu);
    if msorc.verify(&vk_, &ek, &c_, &sig_) {
        println!("====== Randomized Mercurial Signatures are correctly Verified ======");
    } else {
        println!("++++++ Something went wrong in Mercurial Signatures Scheme ++++++");
    }
}

#[allow(non_snake_case, non_camel_case_types)]
fn test_mpc_msorc() {
    let mpc_msorc = MPCMSoRC::new();
    let M = mpc_msorc.msg_gen();
    let (dk, ek) = mpc_msorc.key_gen();
    let c = mpc_msorc.encryption(&ek, &M);
    let r_ = random_z_p();
    let c_ = mpc_msorc.randomize_ciphertext(&ek, &c, &r_);
    if M == mpc_msorc.decryption(&dk, &c_) {
        println!("====== Randomizable Ciphertexts are correctly Decrypted (in multi-party) ======");
    } else {
        println!(
            "++++++ Something went wrong in Randomizable ElGamal Scheme (in multi-party) ++++++"
        );
    }

    let (p0_sk, p1_sk, p0_vk, p1_vk, vk) = mpc_msorc.two_party_sign_key_gen();
    let sig = mpc_msorc.i_sign(&p0_sk, &p1_sk, &p0_vk, &p1_vk, &c, &ek);
    if mpc_msorc.verify(&vk, &ek, &c, &sig) {
        println!("====== Mercurial Signatures are correctly Verified (in 2 party) ======");
    } else {
        println!("++++++ Something went wrong in Mercurial Signatures Scheme (in 2 party) ++++++");
    }

    let vk_ = mpc_msorc.convert_vk(&vk);
    let c_ = mpc_msorc.randomize_ciphertext(&ek, &c, &mpc_msorc.msorc.mu);
    let sig_ = mpc_msorc.adapt(&sig, &mpc_msorc.msorc.rho, &mpc_msorc.msorc.mu);
    if mpc_msorc.verify(&vk_, &ek, &c_, &sig_) {
        println!(
            "====== Randomized Mercurial Signatures are correctly Verified (in 2 party) ======"
        );
    } else {
        println!("++++++ Something went wrong in Mercurial Signatures Scheme (in 2 party) ++++++");
    }
}

#[allow(non_snake_case, non_camel_case_types)]
fn test_mixnets() {
    let mixnets = MixNets::mix_setup(10, 5); // input: (voter_number, mix_server_number)

    let voter_number = mixnets.u;
    let mix_server_number = mixnets.S;
    let (ssk, spk, usk, uvk, ask, avk) = mixnets.mix_key_gen();

    let mut M: Vec<G1Projective> = Vec::with_capacity(voter_number);
    for _ in 0..voter_number {
        M.push(mixnets.msg_gen());
    }

    let mut mix_sig_list: Vec<MixSign> = Vec::with_capacity(voter_number);
    for i in 0..voter_number {
        mix_sig_list.push(mixnets.mix_sign(&usk[i], &uvk[i], &ask, &avk, &M[i]));
    }

    println!("====== Mixnets Signatures are correctly generated ======");

    let init_check = mixnets.mix_init(&mix_sig_list, &uvk, &avk);

    if init_check {
        println!("====== MixInit is Passed ======")
    } else {
        println!("****** MixInit is Passed ******")
    }

    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(voter_number);
    for i in 0..voter_number {
        mix_msg_list.push(MixMsg {
            C: mix_sig_list[i].rndmz_cipher,
            sigma: mix_sig_list[i].sigma,
            vk0: uvk[i][0] + avk[0] + mix_sig_list[i].evk[0],
            vk1: uvk[i][1] + avk[1] + mix_sig_list[i].evk[1],
            vk2: uvk[i][2] + avk[2] + mix_sig_list[i].evk[2],
        })
    }
    let ummixed_msg_list = mix_msg_list.clone();

    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(mix_server_number);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(mix_server_number);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(mix_server_number);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(mix_server_number + 1);

    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for msg in ummixed_msg_list.iter().take(voter_number).skip(1) {
        VK_0 += msg.vk0;
        VK_1 += msg.vk1;
        VK_2 += msg.vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);

    let mut sas_sign = SASSign {
        agg_sig_1: mixnets.mpc_msorc.msorc.g1,
        agg_sig_2: mixnets.w1,
    };

    for j in 0..mix_server_number {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = mixnets.mix(
            &ssk[j],
            &spk[j],
            &mix_msg_list,
            &sas_sign,
            &stored_sas_msg,
            &stored_spk,
        );

        mix_msg_list = shuffled_mix_msg_list;
        sas_sign = sas_sign_j;
        nizk_proving_list.push(nizk_prove_j);
        stored_sas_msg.push(m_j);
        stored_spk.push(spk_j);
        stored_sum_vk.push(vk_j);
    }

    println!("====== Messages are Correctly Mixed ======");
    println!("Length of NIZK proving list: {}", nizk_proving_list.len());
    let verify_check = mixnets.mix_verify(
        &avk,
        &ummixed_msg_list,
        &mix_msg_list,
        &nizk_proving_list,
        &stored_sum_vk,
        &sas_sign,
        &stored_sas_msg,
        &stored_spk,
    );

    if verify_check {
        println!("====== Mixing is Verified ======");
    } else {
        println!("++++++ Mixing isn't Verified ++++++");
    }
}

#[allow(non_snake_case, non_camel_case_types)]
fn test_mixnets_star() {
    let mixnets = MixNets::mix_setup(10, 5); // input: (voter_number, mix_server_number)

    let voter_number = mixnets.u;
    let mix_server_number = mixnets.S;
    let (ssk, spk, usk, uvk, ask, avk) = mixnets.mix_key_gen();

    let mut M: Vec<G1Projective> = Vec::with_capacity(voter_number);
    for _ in 0..voter_number {
        M.push(mixnets.msg_gen());
    }

    let mut mix_sig_list: Vec<MixSign> = Vec::with_capacity(voter_number);
    for i in 0..voter_number {
        mix_sig_list.push(mixnets.mix_sign(&usk[i], &uvk[i], &ask, &avk, &M[i]));
    }

    println!("====== Mixnets Signatures are correctly generated ======");

    let init_check = mixnets.mix_init(&mix_sig_list, &uvk, &avk);

    if init_check {
        println!("====== MixInit is Passed ======")
    } else {
        println!("****** MixInit is Passed ******")
    }

    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(voter_number);
    for i in 0..voter_number {
        mix_msg_list.push(MixMsg {
            C: mix_sig_list[i].rndmz_cipher,
            sigma: mix_sig_list[i].sigma,
            vk0: uvk[i][0] + avk[0] + mix_sig_list[i].evk[0],
            vk1: uvk[i][1] + avk[1] + mix_sig_list[i].evk[1],
            vk2: uvk[i][2] + avk[2] + mix_sig_list[i].evk[2],
        })
    }
    let ummixed_msg_list = mix_msg_list.clone();

    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(mix_server_number);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(mix_server_number);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(mix_server_number);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(mix_server_number + 1);

    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for msg in ummixed_msg_list.iter().take(voter_number).skip(1) {
        VK_0 += msg.vk0;
        VK_1 += msg.vk1;
        VK_2 += msg.vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);

    let mut sas_sign = SASSign {
        agg_sig_1: mixnets.mpc_msorc.msorc.g1,
        agg_sig_2: mixnets.w1,
    };

    for j in 0..mix_server_number {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = mixnets.mix(
            &ssk[j],
            &spk[j],
            &mix_msg_list,
            &sas_sign,
            &stored_sas_msg,
            &stored_spk,
        );

        mix_msg_list = shuffled_mix_msg_list;
        sas_sign = sas_sign_j;
        nizk_proving_list.push(nizk_prove_j);
        stored_sas_msg.push(m_j);
        stored_spk.push(spk_j);
        stored_sum_vk.push(vk_j);
    }

    println!("====== Messages are Correctly Mixed ======");

    let (msk, mpk, _, _, _, _) = mixnets.mix_key_gen();
    let mut msig_list: Vec<G2Projective> = Vec::with_capacity(mix_server_number);
    let mut hashed_mpk_list: Vec<Scalar> = Vec::with_capacity(mix_server_number);
    let eta = digest_into_scalar(
        Hasher::new()
            .update(&stored_sas_msg.last().unwrap().to_bytes_le())
            .finalize(),
    );
    for j in 0..mix_server_number {
        let (msig, hashed_mpk_i) = mixnets.mix_star(&msk[j], &mpk[j], &mpk, &eta);
        msig_list.push(msig);
        hashed_mpk_list.push(hashed_mpk_i);
    }

    let avk_star = G2Projective::multi_exp(&mpk, &hashed_mpk_list);
    let msig = G2Projective::multi_exp(&msig_list, &hashed_mpk_list);
    let verify_check = mixnets.mix_verify_star(
        &avk_star,
        &ummixed_msg_list,
        &mix_msg_list,
        &nizk_proving_list[mix_server_number - 1],
        &stored_sum_vk[mix_server_number - 1],
        &stored_sum_vk[mix_server_number],
        &eta,
        &msig,
    );

    if verify_check {
        println!("====== Mixing is Verified (with star) ======");
    } else {
        println!("++++++ Mixing isn't Verified (with star) ++++++");
    }
}

fn main() {
    println!("****** SINGLE PARTY CASE OF MSoRC ******");
    test_msorc();
    println!("****** MULTI PARTY CASE OF MSoRC ******");
    test_mpc_msorc();
    println!("****** MIXNETS SIGNATURES ******");
    test_mixnets();
    println!("****** MIXNETS SIGNATURES WITH ANOTHER VERIFICATION ******");
    test_mixnets_star();
}
