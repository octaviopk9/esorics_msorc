# Rust Implementaion of A Certified-Input Mixnet from Two-Party Mercurial Signatures on Randomizable Ciphertexts

Library associated with the paper "A Certified-Input Mixnet from Two-Party Mercurial Signatures on Randomizable Ciphertexts", a paper accepted at ESORICS 2025. Implemented by Masaya Nanri (@mnanri)

Disclaimer: This implementation has not been reviewed or audited beyond the authors' scrutiny. It is a prototype implementation, developed for academic purposes to validate the algorithms and protocols presented in the related paper. Some sub-routines are naive implementations whose sole purpose is to provide feasibility results. Therefore, this implementation is not intended to be used "as it is" in production and you should use it at your own risk if you wish to do so.

You can run the benchmark code in this project to obtain a detailed report. The current source code uses a different naming convention compared to the paper. InputCertification is reffered to as MixSign, InputVerification as MixInit, Verify as MixVerify. Besides, some legacy algorithms that are not reported were implemented to evaluate the optimized version where verification takes a single proof (Mix* and MixVerify*). The Sequential Aggregate Signature used is implemented with naming convention "SAS".

## How to run the benchmark

1. Install Rust programing language following instruction like [this](https://www.rust-lang.org/tools/install). If you install it successfully, you can run `cargo --version` command like this:
```
$ cargo --version
cargo 1.75.0 (1d8b05cdd 2023-11-20) # outputed version is depends on your environment.
```

2. Run the command `cargo build` inside the project's directory to produce the binaries.

3. Run the command `cargo bench` to run the benchmark. Benchmarks are based on Criterion, a benchmarking library. This library will print on your console but for extensive statistical results with plots and easy to navigate, Criterion will generate an HTML report under 'target/criterion/report/index.html' in the project folder. Criterion runs the code you give it a varying amount of iterations, depending on the execution time of every run. 

To generate the library's documentation you can run `cargo doc --open`

## Example of result

When you run `cargo bench`, you will get information as in the table shown below, depending on the hardware and versions used. Currently, the `bench.rs` file will measure signature execution times and run the mixing case for n=1K (the rest of the cases are commented out in the code). The number of samples is currently set to 50, but it can be increased to improve accuracy or reduced (down to a minimum of 10) so that the corresponding benchmark takes less time to execute.

MSoRC signature generation algorithms:
| Measured Benchmarks                                             | time[ms] |
| --------------------------------------------------------------- | -------- |
| Generating 1 sign with 2PC-msorc (in Fig.6)                     | 6.472    |
| Generating 1 sign within InputCertification                     | 8.121    |

About MixNets Scheme [sec, n: userrs, N: servers]
| n   | `MixInit` | `Mix` | `MixVerify` (N=10) | `MixVerify` (N=5) | `MixVerify*` | 
| --- | --------- | ----- | ------------------ | ----------------- | ------------ | 
| 1K  | 2.697     | 0.828 | 2.714              | 2.700             | 2.692        |
| 10K | 27.05     | 8.309 | 26.93              | 26.92             | 26.92        |
| 25K | 67.57     | 20.65 | 67.38              | 67.37             | 67.40        | 
| 50K | 135.0     | 41.30 | 134.5              | 134.6             | 134.5        |

### Performance of Minor Components 
- generating pairing `e(g1, g2)` (g1 and g2 are the generators of each group G1 and G2 respectively) -> 379.71 μs

- multi exponentiation of 10 elements -> 737.32 μs

- `SAS.Verify` for 10 pk/messages -> 1.5915 ms
