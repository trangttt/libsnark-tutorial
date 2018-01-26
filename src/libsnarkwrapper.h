//
// Created by trangtt on 1/21/18.
//

#ifndef LIBSNARK_TUTORIAL_LIBSNARKWRAPPER_H
#define LIBSNARK_TUTORIAL_LIBSNARKWRAPPER_H


extern "C" bool setupConstraints(const char* A[],
            const char* B[],
            const char* C[],
            int constraints,
            int variables,
            int inputs,
            const char* pkPath,
            const char* vkPath);

extern "C" bool generateProof(const char* pkPath,
                    const char* publicInputs[],
                    const uint8_t publicInputsLength,
                    const char* privateInputs[],
                    const uint8_t privateInputsLength,
                    const char* proofPath);


// Utilities

template<typename T>
void writeToFile(std::string path, T& obj);

template<typename T>
T loadFromFile(std::string path);


#endif //LIBSNARK_TUTORIAL_LIBSNARKWRAPPER_H
