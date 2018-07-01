//
// Created by jinjun on 18-7-1.
//

#include "compress_perf.hpp"
#include "lz4.h"
#include "crypto_perf.hpp"
#include <chrono>
#include <ed25519/ed25519.h>
#include "display.hpp"
#include "snappy.h"

compress_perf::compress_perf() {

    // Allocate the dataset
    _dataset = allocate_random_dataset();
    _dataset_vector_size = dataset_vector_size;
    _dataset_size = dataset_size;
    _sig_array = new signature_t[dataset_size];
    _iteration = 1;
    _dataset_size = 1;

    public_key_t pubkey;
    private_key_t prikey;

    // Create a keypair
    auto ret = ed25519_create_keypair(&prikey, &pubkey);

    // Generate the ED25519 hash
    for (int data_vector_index = 0; data_vector_index < _dataset_size; data_vector_index++) {
        ed25519_sign(&_sig_array[data_vector_index], _dataset[data_vector_index], 32, &pubkey, &prikey);
        //memcpy(&(_sig_array[data_vector_index].data)[0], "Hello, this is from infiniBlock, please leave your name here",  ed25519_signature_SIZE);
        //memset(&(_sig_array[data_vector_index].data)[0], 0,  ed25519_signature_SIZE);
        //auto s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        //memcpy(&(_sig_array[data_vector_index].data)[0], s, strlen(s));
    }

    // Register the compress functions
    boost::function<int (compress_perf*)> lz4 = &compress_perf::_lz4_perf;
    boost::function<int (compress_perf*)> zstd = &compress_perf::_zstd_perf;
    boost::function<int (compress_perf*)> snappy = &compress_perf::_snappy_perf;
    _m["LZ4"] = lz4;
    _m["ZSTD"] = zstd;
    _m["SNAPPY"] = snappy;
}

compress_perf::~compress_perf() {
    free_random_dataset(_dataset);
    free(_sig_array);
}

void compress_perf::run() {
    uint64_t total = 0;

    for (auto const &func : _m) {
        total = 0;
        std::cout<<func.first<<": ";
        auto start = std::chrono::steady_clock::now();
        for(int i= 0; i < _iteration; i++) {
            total += func.second(this);
        }
        auto end = std::chrono::steady_clock::now();
        auto duaration = std::chrono::duration_cast<std::chrono::milliseconds>(end-start);
        std::cout<<"Ratio:" << ((double)total)/(_iteration * _dataset_size * sizeof(signature_t)) << std::endl;
        std::cout<<"Compress " << (_dataset_size * _iteration * sizeof(signature_t)) / (1024 * 1024) << "M bytes data, used:" << duaration.count() << " milliseconds" << std::endl;
    }


}

int compress_perf::_lz4_perf() {
    char dst[2 * ed25519_signature_SIZE] = {0};
    int total = 0;
    int dst_size = LZ4_compressBound(ed25519_signature_SIZE);

    for (int data_vector_index = 0; data_vector_index < _dataset_size; data_vector_index++) {
        total += LZ4_compress_default((const char*)&(_sig_array[data_vector_index].data)[0], &dst[0], ed25519_signature_SIZE, 2*ed25519_signature_SIZE);
    }

    return total;
}

int compress_perf::_zstd_perf() {
    // ?
    return 0;
}

int compress_perf::_snappy_perf() {
    char dst[2 * ed25519_signature_SIZE] = {0};
    int total = 0;
    size_t dst_size = 0;

    for (int data_vector_index = 0; data_vector_index < _dataset_size; data_vector_index++) {
        snappy::RawCompress((const char*)&(_sig_array[data_vector_index].data)[0], ed25519_signature_SIZE, &dst[0], &dst_size);
        total += dst_size;
    }

    return total;
}