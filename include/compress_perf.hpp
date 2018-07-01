//
// Created by jinjun on 18-7-1.
//

#ifndef CRYPTO_SELECTION_COMPRESS_PERF_HPP
#define CRYPTO_SELECTION_COMPRESS_PERF_HPP


#include <iostream>
#include <boost/function.hpp>
#include <ed25519/ed25519.h>

class compress_perf {
public:
    compress_perf();
    void run();

    ~compress_perf();

private:
    uint8_t **_dataset;
    size_t _dataset_vector_size;
    size_t _dataset_size;
    size_t _iteration;
    signature_t *_sig_array;

    int _lz4_perf(); // K12 Test
    int _snappy_perf();
    int _zstd_perf();
    std::map<std::string, boost::function<int (compress_perf*)>> _m;

};


#endif //CRYPTO_SELECTION_COMPRESS_PERF_HPP
