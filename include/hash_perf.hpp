//
// Created by jinjun on 18-6-29.
//

#ifndef CRYPTO_SELECTION_HASH_PERF_HPP
#define CRYPTO_SELECTION_HASH_PERF_HPP

extern "C" {
#include "KangarooTwelve.h"
#include "KeccakHash.h"
};

#include <iostream>
#include <boost/function.hpp>

class hash_perf {
public:
    hash_perf();
    void run();

    ~hash_perf();

private:
    uint8_t *_dataset;
    const size_t _dataset_size = 1024*1024;
    const size_t _k12_output_len = 256;
    const size_t _iteration = 1024;

    void _k12_perf(); // K12 Test
    void _sha256_perf();
    void _sha3_perf();
    std::map<std::string, boost::function<void(hash_perf*)>> _m;

    //function table
    //std::map<std::string, boost::function<void(hash_perf*)>> m;


};


#endif //CRYPTO_SELECTION_HASH_PERF_HPP
