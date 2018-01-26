import ctypes

lib = ctypes.CDLL('../build/src/libmainlib.so')

A = [[0, 1, 0, 0, 0, 0], [0, 0, 0, 1, 0, 0], [0, 1, 0, 0, 1, 0], [5, 0, 0, 0, 0, 1]];
B = [[0, 1, 0, 0, 0, 0], [0, 1, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0]];
C = [[0, 0, 0, 1, 0, 0], [0, 0, 0, 0, 1, 0], [0, 0, 0, 0, 0, 1], [0, 0, 1, 0, 0, 0]];

S = [1, 3, 35, 9, 27, 30]



def getCharP(A, B, C):
    Astr = [ str(i) for row in A for i in row]
    Bstr = [ str(i) for row in B for i in row]
    Cstr = [ str(i) for row in C for i in row]

    Constraints = ctypes.c_char_p * len(Astr)
    Ap = Constraints()
    Bp = Constraints()
    Cp = Constraints()
    for idx, value in enumerate(Astr):
        Ap[idx] =  ctypes.c_char_p(value.encode())

    for idx, value in enumerate(Bstr):
        Bp[idx] =  ctypes.c_char_p(value.encode())

    for idx, value in enumerate(Cstr):
        Cp[idx] =  ctypes.c_char_p(value.encode())

    return Ap, Bp, Cp

def getInputs(inputs, S):
    publicType = ctypes.c_char_p * inputs
    privateType = ctypes.c_char_p * (len(S) - inputs - 1) # exclude ~one

    publicInputs  = publicType()
    for i in range(inputs):
        publicInputs[i] = ctypes.c_char_p(str(S[i+1]).encode())

    privateInputs = privateType()
    for i in range(inputs+1, len(S)):
        privateInputs[i-inputs-1] = ctypes.c_char_p(str(S[i]).encode())

    return publicInputs, privateInputs



pkPath = ctypes.c_char_p(b"provingKey.bin")
vkPath = ctypes.c_char_p(b"verificationKey.bin")
proofPath = ctypes.c_char_p(b"proof.bin")

variables = 6
inputs = 2
constraints = 4
a, b, c = getCharP(A, B, C)
lib.setupConstraints(a,
                     b,
                     c,
                     constraints,
                     variables,
                     inputs,
                     pkPath,
                     vkPath)

publicInputs, privateInputs = getInputs(inputs, S)

lib.generateProof(pkPath,
                  publicInputs,
                  inputs,
                  privateInputs,
                  variables - inputs - 1,
                  proofPath)
