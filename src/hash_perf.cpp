//
// Created by jinjun on 18-6-29.
//

#include <cstdint>
#include <hash_perf.hpp>
#include <chrono>
#include "openssl/sha.h"

hash_perf::hash_perf() {
    _dataset = new uint8_t[_dataset_size];
    boost::function<void (hash_perf*)> k12 = &hash_perf::_k12_perf;
    boost::function<void (hash_perf*)> sha256 = &hash_perf::_sha256_perf;
    boost::function<void (hash_perf*)> sha3 = &hash_perf::_sha3_perf;
    _m["K12"] = k12;
    _m["SHA256"] = sha256;
    _m["SHA3"] = sha3;

}

hash_perf::~hash_perf() {
    delete _dataset;
}

void hash_perf::run() {

    for (auto const &func : _m) {
        std::cout<<func.first<<": ";
        auto start = std::chrono::steady_clock::now();
        for(int i= 0; i < _iteration; i++) {
            func.second(this);
        }
        auto end = std::chrono::steady_clock::now();
        auto duaration = std::chrono::duration_cast<std::chrono::milliseconds>(end-start);
        std::cout<<"Hash " << (_dataset_size * _iteration) / (1024 * 1024) << "M bytes data, used:" << duaration.count() << " milliseconds" << std::endl;
    }

}

void hash_perf::_k12_perf() {
    const char *customization = "InfiniBlock";
    size_t cus_len = strlen(customization);

    uint8_t output[_k12_output_len] = {0};

    auto ret = KangarooTwelve(_dataset, _dataset_size, &output[0], _k12_output_len, (const uint8_t*)customization, cus_len);
    assert(ret ==0 );
}


void hash_perf::_sha256_perf() {

    uint8_t output[SHA256_DIGEST_LENGTH] = {0};
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, _dataset, _dataset_size);
    SHA256_Final(output, &ctx);
}

void hash_perf::_sha3_perf() {
    Keccak_HashInstance sha3;

    uint8_t output[32] = {0};

    Keccak_HashInitialize_SHA3_256(&sha3);
    Keccak_HashUpdate(&sha3, _dataset, _dataset_size);
    Keccak_HashFinal(&sha3, &output[0]);
}

