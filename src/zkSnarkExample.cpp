//
// Created by trangtt on 1/24/18.
//

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/relations/variable.hpp>


using namespace std;
using namespace libsnark;
using namespace libff;

r1cs_ppzksnark_constraint_system<alt_bn128_pp> createConstraintSystem(){
    r1cs_ppzksnark_constraint_system<alt_bn128_pp> cs;
    int variables = 6;
    int inputs = 2;
    int constraints = 4;

    cs.primary_input_size = inputs; // 2 including output
    cs.auxiliary_input_size = variables - inputs - 1; // =3, ignore ~one

    int a[constraints][variables] = {{0, 1, 0, 0, 0, 0}, {0, 0, 0, 1, 0, 0}, {0, 1, 0, 0, 1, 0}, {5, 0, 0, 0, 0, 1}};
    int b[constraints][variables] = {{0, 1, 0, 0, 0, 0}, {0, 1, 0, 0, 0, 0}, {1, 0, 0, 0, 0, 0}, {1, 0, 0, 0, 0, 0}};
    int c[constraints][variables] = {{0, 0, 0, 1, 0, 0}, {0, 0, 0, 0, 1, 0}, {0, 0, 0, 0, 0, 1}, {0, 0, 1, 0, 0, 0}};

    for(int row=0; row < constraints; row++){
        linear_combination<Fr<alt_bn128_pp>> lnA, lnB, lnC;

        for(int idx=0; idx < variables; idx++){
//            variable<Fr<alt_bn128_pp>> va = variable<Fr<alt_bn128_pp>>(a[row][idx]) ;
//            variable<Fr<alt_bn128_pp>> vb = variable<Fr<alt_bn128_pp>>(b[row][idx]) ;
//            variable<Fr<alt_bn128_pp>> vc = variable<Fr<alt_bn128_pp>>(c[row][idx]) ;
            lnA.add_term(idx, a[row][idx]);
            lnB.add_term(idx, b[row][idx]);
            lnC.add_term(idx, c[row][idx]);
        }
        cs.add_constraint(r1cs_constraint<Fr<alt_bn128_pp>>(lnA, lnB, lnC));

    }
    return cs;
}

r1cs_variable_assignment<Fr<alt_bn128_pp>> getInput(){
    r1cs_variable_assignment<Fr<alt_bn128_pp>> va;
//    va.push_back(1); // ingore ~one
    // primary input
    va.push_back(3); //x
    va.push_back(35); // ~out

    // auxiliary input
    va.push_back(9); // sym_1
    va.push_back(27); // y
    va.push_back(30); // sym_2
    return va;
}

int main () {
    libff::inhibit_profiling_info = true;
    libff::alt_bn128_pp::init_public_params();

    libff::print_header("Create constraint");
    r1cs_ppzksnark_constraint_system<alt_bn128_pp> cs = createConstraintSystem();

    libff::print_header("Generate Key");
    r1cs_ppzksnark_keypair<alt_bn128_pp> keypair = r1cs_ppzksnark_generator<alt_bn128_pp>(cs);

    libff::print_header("Preprocess verification key");
    r1cs_ppzksnark_processed_verification_key<alt_bn128_pp> pvk = r1cs_ppzksnark_verifier_process_vk<alt_bn128_pp>(keypair.vk);

    libff::print_header("R1CS GG-ppzkSNARK Prover");
    r1cs_variable_assignment<Fr<alt_bn128_pp>>  va = getInput();
    r1cs_primary_input<Fr<alt_bn128_pp>> primaryInput(va.begin(), va.begin()+2);
    r1cs_primary_input<Fr<alt_bn128_pp>> auxiliaryInput(va.begin() + 2, va.end());
    r1cs_ppzksnark_proof<alt_bn128_pp> proof = r1cs_ppzksnark_prover<alt_bn128_pp>(keypair.pk, primaryInput, auxiliaryInput);

    libff::print_header("R1CS GG-ppzkSNARK Verifier");
    const bool ans = r1cs_ppzksnark_verifier_strong_IC<alt_bn128_pp>(keypair.vk, primaryInput, proof);
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("R1CS GG-ppzkSNARK Online Verifier");
    const bool ans2 = r1cs_ppzksnark_online_verifier_strong_IC<alt_bn128_pp>(pvk, primaryInput, proof);
    assert(ans2 == ans);


   libff::print_header("Verifier keys");
    alt_bn128_G2 vkA = keypair.vk.alphaA_g2;
    vkA.to_affine_coordinates();

    bigint<alt_bn128_r_limbs> x = vkA.X.c1.as_bigint();
    cout << "Number of bits: " << x.num_bits() << endl;
    char n[64];
    gmp_sprintf(n, "%Nx", x.data, x.N);
    cout << "Hex: " << n << endl;
    cout << "BigInt: " << x << endl;


    return 0;
}