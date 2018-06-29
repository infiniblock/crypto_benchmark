//
// Created by jinjun on 18-6-29.
//

#include <iostream>
#include <cassert>
#include <ed25519/ed25519.h>
#include <chrono>
#include "crypto_perf.hpp"
#include <boost/shared_ptr.hpp>

using namespace std;

void ed25519_basic_test() {
    public_key_t pubkey;
    private_key_t prikey;
    signature_t sig;

    // Create a keypair
    auto ret = ed25519_create_keypair(&prikey, &pubkey);
    assert(ret != 0);

    uint8_t msg[32] = {0};

    ed25519_sign(&sig, msg, 32, &pubkey, &prikey);

    ret = ed25519_verify(&sig, msg, 32, &pubkey);
    assert(ret == 1);
}

void ed25519_perf_test(uint8_t **dataset, long *sign_duaration, long* verify_duaration) {

    public_key_t pubkey;
    private_key_t prikey;
    signature_t sig;

    // Create a keypair
    auto ret = ed25519_create_keypair(&prikey, &pubkey);
    assert(ret != 0);

    // Create sig
    boost::shared_ptr<signature_t[]> sigarray(new signature_t[dataset_size]);


    auto start = std::chrono::steady_clock::now();
    for(int i= 0; i < iteration; i++) {
        for (int data_vector_index = 0; data_vector_index < dataset_size; data_vector_index++) {
            ed25519_sign(&sigarray[data_vector_index], dataset[data_vector_index], 32, &pubkey, &prikey);
        }
    }

    auto end = std::chrono::steady_clock::now();
    auto duaration = std::chrono::duration_cast<std::chrono::milliseconds>(end-start);
    *sign_duaration = duaration.count();


    start = std::chrono::steady_clock::now();
    for(int i= 0; i < iteration; i++) {
        for (int data_vector_index = 0; data_vector_index < dataset_size; data_vector_index++) {
            ret = ed25519_verify(&sigarray[data_vector_index], dataset[data_vector_index], 32, &pubkey);
            assert(ret == 1);
        }
    }

    end = std::chrono::steady_clock::now();
    duaration = std::chrono::duration_cast<std::chrono::milliseconds>(end-start);
    *verify_duaration = duaration.count();

}

void ed25519_perf_thread(int i) {
    auto dataset = allocate_random_dataset();

    long sign_duaration = 0;
    long verify_duaration = 0;
    ed25519_perf_test(dataset, &sign_duaration, &verify_duaration);


    a.lock();
    cout << "In thread "<< i<<endl;
    cout << "Signed " << iteration * dataset_size << " messages, used: " << sign_duaration<< " milliseconds" << endl;
    cout << "Verified " << iteration * dataset_size << " messages, used: " << verify_duaration<< " milliseconds" << endl;
    a.unlock();

    free_random_dataset(dataset);
}

