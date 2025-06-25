use std::vec;

use blake3::Hasher;
use blstrs::*;
use criterion::{criterion_group, criterion_main, Criterion, SamplingMode};
use mixnetslib::mixnets::*;
use mixnetslib::msorc::{random_z_star_p, ElGamalCipherText};

/// Measure the time taken in generating pairings
pub fn generate_pairing(
    scheme: &MixNets,
) {
    let _e = pairing(&G1Affine::from(scheme.mpc_msorc.msorc.g1), &G2Affine::from(scheme.mpc_msorc.msorc.g2));
}

pub fn measure_generate_pairing(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(1, 1);
    c.bench_function("Generate Pairing", |b| b.iter(|| generate_pairing(&scheme)));
}

/// Measure the time taken in multi-exponentiation in G2
pub fn multi_exponentiation(
    g2_base: &[G2Projective],
    scalar_exp: &[Scalar],
) {
    let _sum = G2Projective::multi_exp(&g2_base, &scalar_exp);
}

pub fn measure_multi_exponentiation(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(1, 10);
    let mut g2_base: Vec<G2Projective> = Vec::with_capacity(10);
    unsafe { g2_base.set_len(10) };
    for i in 0..scheme.S {
        g2_base[i] = scheme.mpc_msorc.msorc.g2 * random_z_star_p();
    }
    let mut scalar_exp: Vec<Scalar> = Vec::with_capacity(10);
    unsafe { scalar_exp.set_len(10) };
    for i in 0..scheme.S {
        scalar_exp[i] = random_z_star_p();
    }
    c.bench_function("Multi-Exponentiation of 10 elements in G2", |b| {
        b.iter(|| multi_exponentiation(&g2_base, &scalar_exp))
    });
}

pub fn sas_verify(
    scheme: &MixNets,
    sigma: &SASSign,
    stored_m: &[Scalar],
    stored_spk: &[G2Projective],
) -> bool {
    scheme.sas_verify(sigma, stored_m, stored_spk)
}

pub fn measure_sas_verify(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(10, 10);
    let (ssk, spk, usk, uvk_list, _, _) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, _, sas_sign_j, m_j, spk_j, _) = scheme.mix(
            &ssk[j],
            &spk[j],
            &mix_msg_list,
            &sas_sign,
            &stored_sas_msg,
            &stored_spk,
        );

        mix_msg_list = shuffled_mix_msg_list;
        sas_sign = sas_sign_j;
        stored_sas_msg.push(m_j);
        stored_spk.push(spk_j);
    }

    c.bench_function("Verify the SAS Protocol for 10 pk/messages", |b| {
        b.iter(|| sas_verify(&scheme, &sas_sign, &stored_sas_msg, &stored_spk))
    });
}

/// Measure the time taken in MPC-MSoRC between 2 parties
pub fn mpc_msorc(
    scheme: &MixNets,
    users_count: &usize,
    usk: &Vec<[Scalar; 3]>,
    uvk: &Vec<[G2Projective; 3]>,
    ask: &[Scalar; 3],
    avk: &[G2Projective; 3],
    ciphertexts: &Vec<ElGamalCipherText>,
) {
    for i in 0..*users_count {
        let _sign =
            scheme
                .mpc_msorc
                .i_sign(&usk[i], ask, &uvk[i], avk, &ciphertexts[i], &scheme.ek);
    }
}

pub fn measure_mpc_msorc_1_user(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(1, 1);
    let (_, _, usk, uvk, ask, avk) = scheme.mix_key_gen();
    let ciphertext = vec![scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen())];
    c.bench_function("Generate MPC-MSoRC between 2 parties", |b| {
        b.iter(|| mpc_msorc(&scheme, &scheme.u, &usk, &uvk, &ask, &avk, &ciphertext))
    });
}

/// Measure the time taken to generate a MixSign between User and CA
pub fn mix_sign(
    scheme: &MixNets,
    users_count: &usize,
    usk: &Vec<[Scalar; 3]>,
    uvk: &Vec<[G2Projective; 3]>,
    ask: &[Scalar; 3],
    avk: &[G2Projective; 3],
    messages: &Vec<G1Projective>,
) {
    for i in 0..*users_count {
        let _sign = scheme.mix_sign(&usk[i], &uvk[i], ask, avk, &messages[i]);
    }
}

pub fn measure_mix_sign_1_user(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(1, 1);
    let (_, _, usk, uvk, ask, avk) = scheme.mix_key_gen();
    let message = vec![scheme.msg_gen()];
    c.bench_function("Generate MixSign between an User and CA", |b| {
        b.iter(|| mix_sign(&scheme, &scheme.u, &usk, &uvk, &ask, &avk, &message))
    });
}

/// Measure the time taken to initialize the network

pub fn mix_init(
    scheme: &MixNets,
    mix_sig_list: &Vec<MixSign>,
    uvk_list: &Vec<[G2Projective; 3]>,
    avk: &[G2Projective; 3],
) -> bool {
    scheme.mix_init(mix_sig_list, uvk_list, avk)
}

pub fn measure_mixinit_1000_users_1_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(1000, 1);
    let (_, _, usk, uvk_list, ask, avk) = scheme.mix_key_gen();
    let mut messages: Vec<G1Projective> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        messages.push(scheme.msg_gen());
    }
    let mut mix_sig_list: Vec<MixSign> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_sig_list.push(scheme.mix_sign(&usk[i], &uvk_list[i], &ask, &avk, &messages[i]));
    }
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Initialize the network with 1000 Users and 1 Servers",
        |b| b.iter(|| mix_init(&scheme, &mix_sig_list, &uvk_list, &avk)),
    );
    group.finish();
}

pub fn measure_mixinit_10000_users_1_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(10000, 1);
    let (_, _, usk, uvk_list, ask, avk) = scheme.mix_key_gen();
    let mut messages: Vec<G1Projective> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        messages.push(scheme.msg_gen());
    }
    let mut mix_sig_list: Vec<MixSign> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_sig_list.push(scheme.mix_sign(&usk[i], &uvk_list[i], &ask, &avk, &messages[i]));
    }
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Initialize the network with 10000 Users and 1 Servers",
        |b| b.iter(|| mix_init(&scheme, &mix_sig_list, &uvk_list, &avk)),
    );
    group.finish();
}

pub fn measure_mixinit_25000_users_1_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(25000, 1);
    let (_, _, usk, uvk_list, ask, avk) = scheme.mix_key_gen();
    let mut messages: Vec<G1Projective> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        messages.push(scheme.msg_gen());
    }
    let mut mix_sig_list: Vec<MixSign> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_sig_list.push(scheme.mix_sign(&usk[i], &uvk_list[i], &ask, &avk, &messages[i]));
    }
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Initialize the network with 25000 Users and 1 Servers",
        |b| b.iter(|| mix_init(&scheme, &mix_sig_list, &uvk_list, &avk)),
    );
    group.finish();
}

pub fn measure_mixinit_50000_users_1_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(50000, 1);
    let (_, _, usk, uvk_list, ask, avk) = scheme.mix_key_gen();
    let mut messages: Vec<G1Projective> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        messages.push(scheme.msg_gen());
    }
    let mut mix_sig_list: Vec<MixSign> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_sig_list.push(scheme.mix_sign(&usk[i], &uvk_list[i], &ask, &avk, &messages[i]));
    }
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Initialize the network with 50000 Users and 1 Servers",
        |b| b.iter(|| mix_init(&scheme, &mix_sig_list, &uvk_list, &avk)),
    );
    group.finish();
}

/// Measure the time taken to mix the messages with generating the proofs and signatures
/// We can set arbitrary number of mix servers and voted users
/// We cannot measure overhead of the network communication
pub fn mix(
    scheme: &MixNets,
    ssk: &Vec<Scalar>,
    spk: &Vec<G2Projective>,
    _sign_list: &Vec<MixSign>,
    _uvk_list: &Vec<[G2Projective; 3]>,
    _avk: &[G2Projective; 3],
    mut mix_msg_list: Vec<MixMsg>,
    mut sas_sign: SASSign,
    mut stored_sas_msg: Vec<Scalar>,
    mut stored_spk: Vec<G2Projective>,
    mut nizk_proving_list: Vec<NIZKProve>,
    mut stored_sum_vk: Vec<[G2Projective; 3]>,
) {
    // Initialization
    // let _init_check = scheme.mix_init(sign_list, uvk_list, avk);

    // Mixing
    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
}

#[allow(non_snake_case)]
pub fn measure_mix_1000_users_1_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(1000, 1);
    let (ssk, spk, usk, uvk, ask, avk) = scheme.mix_key_gen();
    let (_, _, esk, evk, _, _) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut sign_list: Vec<MixSign> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        let sk = [
            usk[i][0] + esk[i][0] + ask[0],
            usk[i][1] + esk[i][1] + ask[1],
            usk[i][2] + esk[i][2] + ask[2],
        ];
        sign_list.push(MixSign {
            rndmz_cipher: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&sk, &scheme.ek, &ciphertexts[i]),
            evk: evk[i],
        });
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: sign_list[i].sigma,
            vk0: uvk[i][0] + evk[i][0] + avk[0],
            vk1: uvk[i][1] + evk[i][1] + avk[1],
            vk2: uvk[i][2] + evk[i][2] + avk[2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function("Mix 1000 Messages with a Server", |b| {
        b.iter(|| {
            mix(
                &scheme,
                &ssk,
                &spk,
                &sign_list,
                &uvk,
                &avk,
                mix_msg_list.clone(),
                sas_sign.clone(),
                stored_sas_msg.clone(),
                stored_spk.clone(),
                nizk_proving_list.clone(),
                stored_sum_vk.clone(),
            )
        })
    });
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mix_10000_users_1_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(10000, 1);
    let (ssk, spk, usk, uvk, ask, avk) = scheme.mix_key_gen();
    let (_, _, esk, evk, _, _) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut sign_list: Vec<MixSign> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        let sk = [
            usk[i][0] + esk[i][0] + ask[0],
            usk[i][1] + esk[i][1] + ask[1],
            usk[i][2] + esk[i][2] + ask[2],
        ];
        sign_list.push(MixSign {
            rndmz_cipher: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&sk, &scheme.ek, &ciphertexts[i]),
            evk: evk[i],
        });
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: sign_list[i].sigma,
            vk0: uvk[i][0] + evk[i][0] + avk[0],
            vk1: uvk[i][1] + evk[i][1] + avk[1],
            vk2: uvk[i][2] + evk[i][2] + avk[2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function("Mix 10000 Messages with a Server", |b| {
        b.iter(|| {
            mix(
                &scheme,
                &ssk,
                &spk,
                &sign_list,
                &uvk,
                &avk,
                mix_msg_list.clone(),
                sas_sign.clone(),
                stored_sas_msg.clone(),
                stored_spk.clone(),
                nizk_proving_list.clone(),
                stored_sum_vk.clone(),
            )
        })
    });
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mix_25000_users_1_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(25000, 1);
    let (ssk, spk, usk, uvk, ask, avk) = scheme.mix_key_gen();
    let (_, _, esk, evk, _, _) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut sign_list: Vec<MixSign> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        let sk = [
            usk[i][0] + esk[i][0] + ask[0],
            usk[i][1] + esk[i][1] + ask[1],
            usk[i][2] + esk[i][2] + ask[2],
        ];
        sign_list.push(MixSign {
            rndmz_cipher: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&sk, &scheme.ek, &ciphertexts[i]),
            evk: evk[i],
        });
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: sign_list[i].sigma,
            vk0: uvk[i][0] + evk[i][0] + avk[0],
            vk1: uvk[i][1] + evk[i][1] + avk[1],
            vk2: uvk[i][2] + evk[i][2] + avk[2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function("Mix 25000 Messages with a Server", |b| {
        b.iter(|| {
            mix(
                &scheme,
                &ssk,
                &spk,
                &sign_list,
                &uvk,
                &avk,
                mix_msg_list.clone(),
                sas_sign.clone(),
                stored_sas_msg.clone(),
                stored_spk.clone(),
                nizk_proving_list.clone(),
                stored_sum_vk.clone(),
            )
        })
    });
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mix_50000_users_1_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(50000, 1);
    let (ssk, spk, usk, uvk, ask, avk) = scheme.mix_key_gen();
    let (_, _, esk, evk, _, _) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut sign_list: Vec<MixSign> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        let sk = [
            usk[i][0] + esk[i][0] + ask[0],
            usk[i][1] + esk[i][1] + ask[1],
            usk[i][2] + esk[i][2] + ask[2],
        ];
        sign_list.push(MixSign {
            rndmz_cipher: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&sk, &scheme.ek, &ciphertexts[i]),
            evk: evk[i],
        });
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: sign_list[i].sigma,
            vk0: uvk[i][0] + evk[i][0] + avk[0],
            vk1: uvk[i][1] + evk[i][1] + avk[1],
            vk2: uvk[i][2] + evk[i][2] + avk[2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function("Mix 50000 Messages with a Server", |b| {
        b.iter(|| {
            mix(
                &scheme,
                &ssk,
                &spk,
                &sign_list,
                &uvk,
                &avk,
                mix_msg_list.clone(),
                sas_sign.clone(),
                stored_sas_msg.clone(),
                stored_spk.clone(),
                nizk_proving_list.clone(),
                stored_sum_vk.clone(),
            )
        })
    });
    group.finish();
}

/// Measure the time taken to verify the mixnets protocol
/// Verification becomes heaver as the number of mix servers and voted users increase
pub fn mix_verify(
    scheme: &MixNets,
    avk: &[G2Projective; 3],
    ummixed_msg_list: &Vec<MixMsg>,
    mix_msg_list: &Vec<MixMsg>,
    nizk_proving_list: &Vec<NIZKProve>,
    stored_sum_vk: &Vec<[G2Projective; 3]>,
    sas_sign: &SASSign,
    stored_sas_msg: &Vec<Scalar>,
    stored_spk: &Vec<G2Projective>,
) -> bool {
    scheme.mix_verify(
        avk,
        ummixed_msg_list,
        mix_msg_list,
        nizk_proving_list,
        stored_sum_vk,
        sas_sign,
        stored_sas_msg,
        stored_spk,
    )
}

#[allow(non_snake_case)]
pub fn measure_mixverify_1000_users_5_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(1000, 5);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 1000 Users and 5 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_10000_users_5_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(10000, 5);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 10000 Users and 5 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_25000_users_5_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(25000, 5);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 25000 Users and 5 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_50000_users_5_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(50000, 5);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 50000 Users and 5 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_1000_users_10_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(1000, 10);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 1000 Users and 10 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_10000_users_10_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(10000, 10);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 10000 Users and 10 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_25000_users_10_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(25000, 10);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 25000 Users and 10 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_50000_users_10_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(50000, 10);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 50000 Users and 10 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_1000_users_20_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(1000, 20);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 1000 Users and 20 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_10000_users_20_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(10000, 20);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 10000 Users and 20 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_25000_users_20_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(25000, 20);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 25000 Users and 20 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_50000_users_20_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(50000, 20);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 50000 Users and 20 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_1000_users_50_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(1000, 50);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 1000 Users and 50 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_10000_users_50_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(10000, 50);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 10000 Users and 50 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_25000_users_50_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(25000, 50);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 25000 Users and 50 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_50000_users_50_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(50000, 50);
    let (ssk, spk, usk, uvk_list, _, avk) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "Verify the Mixnets Protocol with 50000 Users and 50 Servers",
        |b| {
            b.iter(|| {
                mix_verify(
                    &scheme,
                    &avk,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    &nizk_proving_list,
                    &stored_sum_vk,
                    &sas_sign,
                    &stored_sas_msg,
                    &stored_spk,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn mix_verify_star(
    scheme: &MixNets,
    avk: &G2Projective,
    ummixed_msg_list: &Vec<MixMsg>,
    mixed_msg_list: &Vec<MixMsg>,
    proof: &NIZKProve,
    A: &[G2Projective; 3],
    x: &[G2Projective; 3],
    eta: &Scalar,
    msig: &G2Projective,
) -> bool {
    scheme.mix_verify_star(
        avk,
        ummixed_msg_list,
        mixed_msg_list,
        proof,
        A,
        x,
        eta,
        msig,
    )
}

#[allow(non_snake_case)]
pub fn measure_mixverify_star_1000_users_5_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(1000, 5);
    let (ssk, spk, usk, uvk_list, _, _) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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

    let (msk, mpk, _, _, _, _) = scheme.mix_key_gen();
    let mut msig_list: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut hashed_mpk_list: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let eta = digest_into_scalar(
        Hasher::new()
            .update(&stored_sas_msg[scheme.S - 1].to_bytes_le())
            .finalize(),
    );
    for j in 0..scheme.S {
        let (msig, hashed_mpk_i) = scheme.mix_star(&msk[j], &mpk[j], &mpk, &eta);
        msig_list.push(msig);
        hashed_mpk_list.push(hashed_mpk_i);
    }
    let avk_star = G2Projective::multi_exp(&mpk, &hashed_mpk_list);
    let msig = G2Projective::multi_exp(&msig_list, &hashed_mpk_list);
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "MixVerify* (Msig mode) Protocol with 1000 Users and 5 Servers",
        |b| {
            b.iter(|| {
                mix_verify_star(
                    &scheme,
                    &avk_star,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    nizk_proving_list.last().unwrap(),
                    &stored_sum_vk[scheme.S - 1],
                    &stored_sum_vk.last().unwrap(),
                    &eta,
                    &msig,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_star_10000_users_5_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(10000, 5);
    let (ssk, spk, usk, uvk_list, _, _) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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

    let (msk, mpk, _, _, _, _) = scheme.mix_key_gen();
    let mut msig_list: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut hashed_mpk_list: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let eta = digest_into_scalar(
        Hasher::new()
            .update(&stored_sas_msg[scheme.S - 1].to_bytes_le())
            .finalize(),
    );
    for j in 0..scheme.S {
        let (msig, hashed_mpk_i) = scheme.mix_star(&msk[j], &mpk[j], &mpk, &eta);
        msig_list.push(msig);
        hashed_mpk_list.push(hashed_mpk_i);
    }
    let avk_star = G2Projective::multi_exp(&mpk, &hashed_mpk_list);
    let msig = G2Projective::multi_exp(&msig_list, &hashed_mpk_list);
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "MixVerify* (Msig mode) Protocol with 10000 Users and 5 Servers",
        |b| {
            b.iter(|| {
                mix_verify_star(
                    &scheme,
                    &avk_star,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    nizk_proving_list.last().unwrap(),
                    &stored_sum_vk[scheme.S - 1],
                    &stored_sum_vk.last().unwrap(),
                    &eta,
                    &msig,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_star_25000_users_5_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(25000, 5);
    let (ssk, spk, usk, uvk_list, _, _) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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

    let (msk, mpk, _, _, _, _) = scheme.mix_key_gen();
    let mut msig_list: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut hashed_mpk_list: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let eta = digest_into_scalar(
        Hasher::new()
            .update(&stored_sas_msg[scheme.S - 1].to_bytes_le())
            .finalize(),
    );
    for j in 0..scheme.S {
        let (msig, hashed_mpk_i) = scheme.mix_star(&msk[j], &mpk[j], &mpk, &eta);
        msig_list.push(msig);
        hashed_mpk_list.push(hashed_mpk_i);
    }
    let avk_star = G2Projective::multi_exp(&mpk, &hashed_mpk_list);
    let msig = G2Projective::multi_exp(&msig_list, &hashed_mpk_list);
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "MixVerify* (Msig mode) Protocol with 25000 Users and 5 Servers",
        |b| {
            b.iter(|| {
                mix_verify_star(
                    &scheme,
                    &avk_star,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    nizk_proving_list.last().unwrap(),
                    &stored_sum_vk[scheme.S - 1],
                    &stored_sum_vk.last().unwrap(),
                    &eta,
                    &msig,
                )
            })
        },
    );
    group.finish();
}

#[allow(non_snake_case)]
pub fn measure_mixverify_star_50000_users_5_servers(c: &mut Criterion) {
    let scheme = MixNets::mix_setup(50000, 5);
    let (ssk, spk, usk, uvk_list, _, _) = scheme.mix_key_gen();
    let mut ciphertexts: Vec<ElGamalCipherText> = Vec::with_capacity(scheme.u);
    for _ in 0..scheme.u {
        ciphertexts.push(scheme.mpc_msorc.encryption(&scheme.ek, &scheme.msg_gen()));
    }
    let mut mix_msg_list: Vec<MixMsg> = Vec::with_capacity(scheme.u);
    for i in 0..scheme.u {
        mix_msg_list.push(MixMsg {
            C: ciphertexts[i],
            sigma: scheme
                .mpc_msorc
                .msorc
                .sign(&usk[i], &scheme.ek, &ciphertexts[i]),
            vk0: uvk_list[i][0],
            vk1: uvk_list[i][1],
            vk2: uvk_list[i][2],
        });
    }
    let ummixed_msg_list = mix_msg_list.clone();
    let mut stored_sas_msg: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let mut stored_spk: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut nizk_proving_list: Vec<NIZKProve> = Vec::with_capacity(scheme.S);
    let mut stored_sum_vk: Vec<[G2Projective; 3]> = Vec::with_capacity(scheme.S + 1);
    let mut VK_0 = ummixed_msg_list[0].vk0;
    let mut VK_1 = ummixed_msg_list[0].vk1;
    let mut VK_2 = ummixed_msg_list[0].vk2;
    for i in 1..scheme.u {
        VK_0 += ummixed_msg_list[i].vk0;
        VK_1 += ummixed_msg_list[i].vk1;
        VK_2 += ummixed_msg_list[i].vk2;
    }
    stored_sum_vk.push([VK_0, VK_1, VK_2]);
    let mut sas_sign = SASSign {
        agg_sig_1: scheme.mpc_msorc.msorc.g1,
        agg_sig_2: scheme.w1,
    };

    for j in 0..scheme.S {
        let (shuffled_mix_msg_list, nizk_prove_j, sas_sign_j, m_j, spk_j, vk_j) = scheme.mix(
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

    let (msk, mpk, _, _, _, _) = scheme.mix_key_gen();
    let mut msig_list: Vec<G2Projective> = Vec::with_capacity(scheme.S);
    let mut hashed_mpk_list: Vec<Scalar> = Vec::with_capacity(scheme.S);
    let eta = digest_into_scalar(
        Hasher::new()
            .update(&stored_sas_msg[scheme.S - 1].to_bytes_le())
            .finalize(),
    );
    for j in 0..scheme.S {
        let (msig, hashed_mpk_i) = scheme.mix_star(&msk[j], &mpk[j], &mpk, &eta);
        msig_list.push(msig);
        hashed_mpk_list.push(hashed_mpk_i);
    }
    let avk_star = G2Projective::multi_exp(&mpk, &hashed_mpk_list);
    let msig = G2Projective::multi_exp(&msig_list, &hashed_mpk_list);
    let mut group = c.benchmark_group("flat-sampling-example");
    group.sample_size(50);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function(
        "MixVerify* (Msig mode) Protocol with 50000 Users and 5 Servers",
        |b| {
            b.iter(|| {
                mix_verify_star(
                    &scheme,
                    &avk_star,
                    &ummixed_msg_list,
                    &mix_msg_list,
                    nizk_proving_list.last().unwrap(),
                    &stored_sum_vk[scheme.S - 1],
                    &stored_sum_vk.last().unwrap(),
                    &eta,
                    &msig,
                )
            })
        },
    );
    group.finish();
}


criterion_group!(
    benches,
    measure_mix_sign_1_user,
    measure_mpc_msorc_1_user,
    measure_mixinit_1000_users_1_servers,
    measure_mixinit_10000_users_1_servers,
    measure_mixinit_25000_users_1_servers,
    measure_mixinit_50000_users_1_servers,
    measure_mix_1000_users_1_servers,
    measure_mix_10000_users_1_servers,
    measure_mix_25000_users_1_servers,
    measure_mix_50000_users_1_servers,
    measure_mixverify_1000_users_5_servers,
    measure_mixverify_10000_users_5_servers,
    measure_mixverify_25000_users_5_servers,
    measure_mixverify_50000_users_5_servers,
    measure_mixverify_1000_users_10_servers,
    measure_mixverify_10000_users_10_servers,
    measure_mixverify_25000_users_10_servers,
    measure_mixverify_50000_users_10_servers,
    measure_mixverify_1000_users_20_servers,
    measure_mixverify_10000_users_20_servers,
    measure_mixverify_25000_users_20_servers,
    measure_mixverify_50000_users_20_servers,
    measure_mixverify_1000_users_50_servers,
    measure_mixverify_10000_users_50_servers,
    measure_mixverify_25000_users_50_servers,
    measure_mixverify_50000_users_50_servers,
    measure_mixverify_star_1000_users_5_servers,
    measure_mixverify_star_10000_users_5_servers,
    measure_mixverify_star_25000_users_5_servers,
    measure_mixverify_star_50000_users_5_servers,
    
    measure_generate_pairing,
    measure_multi_exponentiation,
    measure_sas_verify
);

criterion_main!(benches);
