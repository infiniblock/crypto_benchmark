//
// Created by jinjun on 18-6-27.
//

#ifndef CPP_STUDY_SODIUM_STUDY_HPP
#define CPP_STUDY_SODIUM_STUDY_HPP

#include <iostream>
#include <secp256k1.h>
#include <boost/thread.hpp>

#define SECP256K1_SK_BYTES 32
#define SECP256K1_MSG_BYTES 32
#define SECP256K1_PUB_KEY 33

class crypto_perf{
public:
    crypto_perf();
    void run();

    ~crypto_perf();
    secp256k1_context *secp256k1_context1;

private:
    void _test_sodium_signature();

    // for secp
    void _test_secp256k1_sign_verify();
};

extern const size_t dataset_size;
extern const size_t dataset_vector_size;
extern const size_t iteration;

extern uint8_t ** allocate_random_dataset();
extern void free_random_dataset(uint8_t ** dataset);

extern boost::mutex a;

#endif //CPP_STUDY_SODIUM_STUDY_HPP
