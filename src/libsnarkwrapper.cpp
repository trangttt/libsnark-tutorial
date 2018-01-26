//
// Created by trangtt on 1/21/18.
//

#include <fstream>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/relations/variable.hpp>

#include "libsnarkwrapper.h"

using namespace std;
using namespace libsnark;
using namespace libff;

#ifdef LIBSNARK_DEBUG
    #define debug printf
#else
    #define debug
#endif

r1cs_ppzksnark_constraint_system<alt_bn128_pp> createConstraintSystem(const char* A[],
                                                                      const char* B[],
                                                                      const char* C[],
                                                                      int constraints,
                                                                      int variables,
                                                                      int inputs
    ){
    r1cs_ppzksnark_constraint_system<alt_bn128_pp> cs;

    cs.primary_input_size = inputs; // 2 including output
    cs.auxiliary_input_size = variables - inputs - 1; // =3, ignore ~one

    for(int row=0; row < constraints; row++){
        linear_combination<Fr<alt_bn128_pp>> lnA, lnB, lnC;

        for(int idx=0; idx < variables; idx++){
            lnA.add_term(idx, bigint<alt_bn128_r_limbs>(A[row * variables +idx]));
            lnB.add_term(idx, bigint<alt_bn128_r_limbs>(B[row * variables + idx]));
            lnC.add_term(idx, bigint<alt_bn128_r_limbs>(C[row * variables + idx]));
        }
        cs.add_constraint(r1cs_constraint<Fr<alt_bn128_pp>>(lnA, lnB, lnC));

    }
    return cs;
}


extern "C" bool setupConstraints(const char* A[],
            const char* B[],
            const char* C[],
            int constraints,
            int variables,
            int inputs,
            const char* pkPath,
            const char* vkPath){

    inhibit_profiling_info = true;
    inhibit_profiling_counters = true;

    alt_bn128_pp::init_public_params();

    libff::print_header("Create constraints");
    r1cs_ppzksnark_constraint_system<alt_bn128_pp> cs = createConstraintSystem(A, B, C, constraints, variables, inputs);

    libff::print_header("Generate keys");
    r1cs_ppzksnark_keypair<alt_bn128_pp> keypair = r1cs_ppzksnark_generator<alt_bn128_pp>(cs);

    libff::print_header("Export verification keys");
    writeToFile<r1cs_ppzksnark_verification_key<alt_bn128_pp>>(vkPath, keypair.vk);

    libff::print_header("Export proving keys");
    writeToFile<r1cs_ppzksnark_proving_key<alt_bn128_pp>>(pkPath, keypair.pk);
    return true;
};

extern "C" bool generateProof(const char* pkPath,
                    const char* publicInputs[],
                    const uint8_t publicInputsLength,
                    const char* privateInputs[],
                    const uint8_t privateInputsLength,
                    const char* proofPath){

    inhibit_profiling_info = true;
    inhibit_profiling_counters = true;

    alt_bn128_pp::init_public_params();

    libff::print_header("Import keys");
    r1cs_ppzksnark_proving_key<alt_bn128_pp> pk = loadFromFile<r1cs_ppzksnark_proving_key<alt_bn128_pp>>(pkPath);


    libff::print_header("Setup variable assignment");
    r1cs_variable_assignment<Fr<alt_bn128_pp>> va;

    for(int i=0; i < publicInputsLength; i++ ){
        va.push_back(bigint<alt_bn128_r_limbs>(publicInputs[i]));
    }

    for(int i=0; i < privateInputsLength; i++ ){
        va.push_back(bigint<alt_bn128_r_limbs>(privateInputs[i]));
    }

    r1cs_primary_input<Fr<alt_bn128_pp>> primaryInput(va.begin(), va.begin()+ publicInputsLength);
    r1cs_primary_input<Fr<alt_bn128_pp>> auxiliaryInput(va.begin() + publicInputsLength, va.end());

    libff::print_header("Generate proof");
    r1cs_ppzksnark_proof<alt_bn128_pp> proof = r1cs_ppzksnark_prover<alt_bn128_pp>(pk, primaryInput, auxiliaryInput);


    libff::print_header("Export proof");
    writeToFile(proofPath, proof);
    return true;
}

/////////////////////////
// Utilities
/////////////////////////

template<typename T>
void writeToFile(std::string path, T& obj) {
    std::stringstream ss;
    ss << obj;
    std::ofstream fh(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}



template<typename T>
T loadFromFile(std::string path) {
    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);

    assert(fh.is_open());

    ss << fh.rdbuf();
    fh.close();

    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    T obj;
    ss >> obj;

    return obj;
}

