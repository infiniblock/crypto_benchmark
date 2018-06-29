//
// Created by jinjun on 18-6-27.
//

#include "crypto_perf.hpp"
#include <iostream>
#include <sodium.h>
#include "display.hpp"
#include <boost/shared_ptr.hpp>
#include <vector>
#include <chrono>
#include <secp256k1.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include "ed25519_perf.hpp"

using std::cout;
using std::endl;
using display::displayTitle;
using display::printCharInHex;


/*
 * The data set is 1000 random data,  the data len is 32byte
 */
const size_t dataset_size = 1000;
const size_t dataset_vector_size = 32;
const size_t iteration = 1;
boost::mutex a;

// Test Sig performance
// Generate the dataset, for avoiding the cache
uint8_t ** allocate_random_dataset() {
    using namespace boost;

    auto **ret = new uint8_t* [dataset_size];

    for (int i = 0; i < dataset_size; i++) {
        ret[i] = new uint8_t[dataset_vector_size];
        // Generate the random data
        randombytes_buf(ret[i], dataset_vector_size);
    }

    return ret;
}

void free_random_dataset(uint8_t ** dataset) {
    for (int i = 0; i < dataset_size; i++) {
        delete(dataset[i]);
    }

    delete(dataset);
}

static uint8_t ** allocate_sig_msg_buf(size_t sign_bytes) {
    auto sig_ret = new uint8_t*[dataset_size];
    for (int i= 0; i < dataset_size; i++) {
        sig_ret[i] = new uint8_t[sign_bytes + dataset_vector_size];
    }
    return sig_ret;
}

/*
 * Try to understant libsodium lib.
 */
void crypto_perf::_test_sodium_signature() {

    const char *msg = "test";
    u_int8_t sk[crypto_sign_SECRETKEYBYTES];
    u_int8_t pk[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_keypair(pk, sk);
    u_int8_t sig[crypto_sign_BYTES + 4];
    u_int64_t sig_msg_len = 0;

    crypto_sign(sig, (unsigned long long*)&sig_msg_len, (const unsigned char*)msg, 4, sk);


    u_int8_t unsig_msg[4];
    u_int64_t unsig_msg_len= 0;

    if (crypto_sign_open(&unsig_msg[0], (unsigned long long*)&unsig_msg_len, sig, sig_msg_len, pk)) {
        cout<<"Msg mismatch"<<endl;
    }
}


static long perf_crypto_sign(uint8_t **dataset, uint8_t sk[crypto_sign_SECRETKEYBYTES], uint8_t** sig_ret) {

    //2. Prepare the pk and sk
    u_int64_t sig_msg_len = 0;


    // 4. Measure it
    auto start = std::chrono::steady_clock::now();
    for(int i= 0; i < iteration; i++) {
        for(int data_vector_index = 0; data_vector_index < dataset_size; data_vector_index++) {
            auto dataset_vector = dataset[data_vector_index];
            crypto_sign(sig_ret[data_vector_index], (unsigned long long*)&sig_msg_len, (const unsigned char*)dataset_vector, dataset_vector_size, sk);
        }

    }

    auto end = std::chrono::steady_clock::now();
    auto duaration = std::chrono::duration_cast<std::chrono::milliseconds>(end-start);
    //x. free the data


    return duaration.count();
}

static long perf_crypto_verify(uint8_t ** sig_msg, uint8_t pk[crypto_sign_PUBLICKEYBYTES]) {

    u_int8_t unsig_msg[dataset_vector_size];
    u_int64_t unsig_msg_len= 0;

    auto start = std::chrono::steady_clock::now();
    for(int i= 0; i < iteration; i++) {
        for (int data_vector_index = 0; data_vector_index < dataset_size; data_vector_index++) {
            if (crypto_sign_open(&unsig_msg[0], (unsigned long long *) &unsig_msg_len, sig_msg[data_vector_index], crypto_sign_BYTES + dataset_vector_size, pk)) {
                cout << "Msg mismatch" << endl;
            }
        }
    }

    auto end = std::chrono::steady_clock::now();
    auto duaration = std::chrono::duration_cast<std::chrono::milliseconds>(end-start);

    return duaration.count();
}

// Multithread sign and verification perf

static void perf_sign_verify (int i) {
    auto dataset = allocate_random_dataset();
    auto sig_ret = allocate_sig_msg_buf(crypto_sign_BYTES);
    u_int8_t sk[crypto_sign_SECRETKEYBYTES];
    u_int8_t pk[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_keypair(pk, sk);

    auto sign_duration = perf_crypto_sign(dataset, sk, sig_ret);
    auto verify_duaration = perf_crypto_verify(sig_ret, pk);

    a.lock();
    cout << "In thread "<< i<<endl;
    cout << "Signed " << iteration * dataset_size << " messages, used: " << sign_duration<< " milliseconds" << endl;
    cout << "Verified " << iteration * dataset_size << " messages, used: " << verify_duaration<< " milliseconds" << endl;
    a.unlock();

    free_random_dataset(sig_ret);
    free_random_dataset(dataset);
}

static void multi_thread_sig_perf() {
    // Only 4 CPU in my CPU
    using boost::thread;
    std::vector<thread*> tv;

    for (int i = 0; i < boost::thread::hardware_concurrency(); i++) {
        tv.emplace_back(new thread(perf_sign_verify, i));
    }

    for (auto t : tv) {
        t->join();
    }

}

/*
 * Try to understand bitcoin's libsecp256k1
 */
void crypto_perf::_test_secp256k1_sign_verify() {

    uint8_t sk[SECP256K1_SK_BYTES] = {1};  // you can set to any value
    secp256k1_ecdsa_signature sig;
    uint8_t msg_hash[SECP256K1_MSG_BYTES] = {0}; // Any value which the msg can generated
    uint8_t sig_out[SECP256K1_MSG_BYTES + 32 + 8];
    size_t sig_out_len = sizeof(sig_out);
    secp256k1_pubkey pubkey;
    uint8_t pk[SECP256K1_PUB_KEY];
    size_t pk_len = sizeof(pk);

    auto ret = secp256k1_ecdsa_sign(this->secp256k1_context1,
                         &sig,
                         &msg_hash[0],
                         &sk[0],
                         nullptr,
                         nullptr
    );

    assert(ret == 1);
    // Everything is at sig, get it from the sig
    ret = secp256k1_ecdsa_signature_serialize_der(this->secp256k1_context1, &sig_out[0], &sig_out_len, &sig);
    assert(ret == 1);

    // Generate pub key
    ret = secp256k1_ec_pubkey_create(this->secp256k1_context1, &pubkey, &sk[0]);
    assert(ret == 1);

    ret = secp256k1_ec_pubkey_serialize(this->secp256k1_context1, &pk[0], &pk_len, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(ret == 1);

    // Parse the pubkey
    ret = secp256k1_ec_pubkey_parse(this->secp256k1_context1, &pubkey, &pk[0], pk_len);
    assert(ret == 1);

    ret = secp256k1_ecdsa_signature_parse_der(this->secp256k1_context1, &sig, &sig_out[0], sig_out_len);
    assert(ret == 1);

    ret = secp256k1_ecdsa_verify(this->secp256k1_context1, &sig, &msg_hash[0], &pubkey);
    assert(ret == 1);
}

// The secp256 part
long perf_secp256k1_sign(crypto_perf* sec, uint8_t **dataset, uint8_t sk[SECP256K1_SK_BYTES], uint8_t** sig_ret) {

    secp256k1_ecdsa_signature sig;
    size_t sig_out_len = 72;

    auto start = std::chrono::steady_clock::now();
    for(int i= 0; i < iteration; i++) {
        for (int data_vector_index = 0; data_vector_index < dataset_size; data_vector_index++) {

            secp256k1_ecdsa_signature sig;
            auto ret = secp256k1_ecdsa_sign(sec->secp256k1_context1,
                                            &sig,
                                            dataset[data_vector_index],
                                            &sk[0],
                                            nullptr,
                                            nullptr
            );
            assert(ret == 1);
            // Everything is at sig, get it from the sig
            sig_out_len = 72;
            ret = secp256k1_ecdsa_signature_serialize_der(sec->secp256k1_context1, sig_ret[data_vector_index], &sig_out_len, &sig);
            sig_ret[data_vector_index][71] = (char)sig_out_len;
            assert(ret == 1);
        }
    }
    auto end = std::chrono::steady_clock::now();
    auto duaration = std::chrono::duration_cast<std::chrono::milliseconds>(end-start);

    return duaration.count();
}

long perf_secp256k1_verify(crypto_perf* sec, uint8_t **sig_msg, uint8_t **dataset, uint8_t *sk) {

    size_t sig_out_len = 72;
    secp256k1_pubkey pubkey;

    // Generate pub key
    auto ret = secp256k1_ec_pubkey_create(sec->secp256k1_context1, &pubkey, &sk[0]);
    assert(ret == 1);


    auto start = std::chrono::steady_clock::now();
    for(int i= 0; i < iteration; i++) {
        for (int data_vector_index = 0; data_vector_index < dataset_size; data_vector_index++) {

            secp256k1_ecdsa_signature sig;
            sig_out_len = sig_msg[data_vector_index][71];
            ret = secp256k1_ecdsa_signature_parse_der(sec->secp256k1_context1, &sig, sig_msg[data_vector_index], sig_out_len);
            assert(ret == 1);

            ret = secp256k1_ecdsa_verify(sec->secp256k1_context1, &sig, dataset[data_vector_index], &pubkey);
            assert(ret == 1);

        }
    }
    auto end = std::chrono::steady_clock::now();
    auto duaration = std::chrono::duration_cast<std::chrono::milliseconds>(end-start);

    return duaration.count();
}

void secp256k1_perf_sign_verify (crypto_perf* sec, int i) {

    auto dataset = allocate_random_dataset();
    auto secp256k1_sig_out = allocate_sig_msg_buf(40);
    u_int8_t sk[SECP256K1_SK_BYTES] = {1};

    auto sign_duration = perf_secp256k1_sign(sec, dataset, sk, secp256k1_sig_out);
    auto verify_duaration = perf_secp256k1_verify(sec, secp256k1_sig_out, dataset, sk);

    a.lock();
    cout << "In thread "<< i<<endl;
    cout << "Signed " << iteration * dataset_size << " messages, used: " << sign_duration<< " milliseconds" << endl;
    cout << "Verified " << iteration * dataset_size << " messages, used: " << verify_duaration<< " milliseconds" << endl;
    a.unlock();

    free_random_dataset(secp256k1_sig_out);
    free_random_dataset(dataset);
}

void multi_thread_secp256k1_perf(crypto_perf* sec) {
    // Only 4 CPU in my CPU

    using boost::thread;
    std::vector<thread*> tv;

    for (int i = 0; i < boost::thread::hardware_concurrency(); i++) {
        tv.emplace_back(new thread(secp256k1_perf_sign_verify, sec, i));
    }

    for (auto t : tv) {
        t->join();
    }

}

// RSA part

static EVP_PKEY* rsa_generate_keypair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    assert(ctx != nullptr);

    auto ret = EVP_PKEY_keygen_init(ctx);
    assert(ret == 1);

    ret = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    assert(ret == 1);

    EVP_PKEY *ppkey = nullptr;
    ret = EVP_PKEY_keygen(ctx, &ppkey);
    assert(ret == 1);
    assert(ppkey != nullptr);

    return ppkey;
}

static void rsa_free_keypair(EVP_PKEY* ppkey) {
    EVP_PKEY_free(ppkey);
}


static void rsa_sign(const char*msg, size_t msglen, uint8_t *sig_ret, uint32_t *sig_ret_len,  EVP_PKEY *ppkey) {

    EVP_MD_CTX *mctx = nullptr;
    size_t siglen = 0;

    mctx = EVP_MD_CTX_create();
    assert(mctx != nullptr);

    auto ret = EVP_DigestSignInit(mctx, nullptr, EVP_sha256(), nullptr, ppkey);
    assert(ret == 1);

    ret = EVP_DigestSignUpdate(mctx, msg, msglen);
    assert(ret == 1);

    ret = EVP_DigestSignFinal(mctx, nullptr, &siglen);
    assert(ret == 1);
    assert(siglen <= *sig_ret_len);

    ret = EVP_DigestSignFinal(mctx, sig_ret, &siglen);
    assert(ret == 1);

    *sig_ret_len = (uint32_t)siglen;

    EVP_MD_CTX_destroy(mctx);
}

static void rsa_verify(const char*msg, size_t msglen, uint8_t *sig_ret, uint32_t sig_ret_len, EVP_PKEY *ppkey) {

    EVP_MD_CTX *mctx = nullptr;
    mctx = EVP_MD_CTX_create();
    assert(mctx != nullptr);

    auto ret = EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, ppkey);
    assert(ret == 1);

    ret = EVP_DigestSignUpdate(mctx, msg, msglen);
    assert(ret == 1);

    ret = EVP_DigestVerifyFinal(mctx, sig_ret, sig_ret_len);
    assert(ret == 1);

    EVP_MD_CTX_destroy(mctx);
}


static void rsa_sign_verify() {
    // 1 generate a key

    EVP_PKEY *ppkey= rsa_generate_keypair();

    const char *msg = "Hello, Infiniblock!";
    uint8_t sig_ret[512] = {0};
    uint32_t sig_len = sizeof(sig_ret);

    rsa_sign(msg, strlen(msg), &sig_ret[0], &sig_len, ppkey);
    rsa_verify(msg, strlen(msg), &sig_ret[0], sig_len, ppkey);

    rsa_free_keypair(ppkey);
}

// RSA Perf Test
long perf_rsa_sign(uint8_t **sig, uint8_t **dataset, EVP_PKEY *ppkey) {

    size_t sig_out_len = 512; // It's a big problem


    auto start = std::chrono::steady_clock::now();
    for(int i= 0; i < iteration; i++) {
        for (int data_vector_index = 0; data_vector_index < dataset_size; data_vector_index++) {
            rsa_sign((const char*)dataset[data_vector_index], 32, sig[data_vector_index], (uint32_t*)&sig_out_len, ppkey);
            // the sig out len , should be 256, fixed value
        }
    }
    auto end = std::chrono::steady_clock::now();
    auto duaration = std::chrono::duration_cast<std::chrono::milliseconds>(end-start);

    return duaration.count();
}

long perf_rsa_verify(uint8_t **sig, uint8_t **dataset, EVP_PKEY *ppkey) {

    auto start = std::chrono::steady_clock::now();
    for(int i= 0; i < iteration; i++) {
        for (int data_vector_index = 0; data_vector_index < dataset_size; data_vector_index++) {
            rsa_verify((const char*)dataset[data_vector_index], 32, sig[data_vector_index], 256, ppkey);
            // the sig out len , should be 256, fixed value
        }
    }
    auto end = std::chrono::steady_clock::now();
    auto duaration = std::chrono::duration_cast<std::chrono::milliseconds>(end-start);

    return duaration.count();
}

static void rsa_perf_sign_verify (int i) {

    auto dataset = allocate_random_dataset();
    auto rsa_sig_ret = allocate_sig_msg_buf(512-dataset_vector_size);
    EVP_PKEY *ppkey= rsa_generate_keypair();


    auto sign_duaration = perf_rsa_sign(rsa_sig_ret, dataset, ppkey);
    auto verify_duaration = perf_rsa_verify(rsa_sig_ret, dataset, ppkey);

    a.lock();
    cout << "In thread "<< i<<endl;
    cout << "Signed " << iteration * dataset_size << " messages, used: " << sign_duaration<< " milliseconds" << endl;
    cout << "Verified " << iteration * dataset_size << " messages, used: " << verify_duaration<< " milliseconds" << endl;
    a.unlock();

    free_random_dataset(rsa_sig_ret);
    free_random_dataset(dataset);
}

void multi_thread_rsa_perf() {
    // Only 4 CPU in my CPU

    using boost::thread;
    std::vector<thread*> tv;

    for (int i = 0; i < boost::thread::hardware_concurrency(); i++) {
        tv.emplace_back(new thread(rsa_perf_sign_verify, i));
    }

    for (auto t : tv) {
        t->join();
    }

}

// amd-64-24k implementation perf
void multi_thread_ed25519_perf() {
    // Only 4 CPU in my CPU

    using boost::thread;
    std::vector<thread*> tv;

    for (int i = 0; i < boost::thread::hardware_concurrency(); i++) {
        tv.emplace_back(new thread(ed25519_perf_thread, i));
    }

    for (auto t : tv) {
        t->join();
    }

}

void crypto_perf::run(){
    u_int8_t sk[crypto_sign_SECRETKEYBYTES];
    u_int8_t pk[crypto_sign_PUBLICKEYBYTES];
    auto dataset = allocate_random_dataset();

    displayTitle("Secp256K1(bitcoin) Basic Test");
    this->_test_secp256k1_sign_verify();
    cout<<"Success" << endl;

    displayTitle("secp256k1(bitcoin) Perf Test");
    auto secp256k1_sig_out = allocate_sig_msg_buf(40);
    auto sign_duration = perf_secp256k1_sign(this, dataset, sk, secp256k1_sig_out);
    cout << "Signed " << iteration * dataset_size << " messages, used: " << sign_duration<< " milliseconds" << endl;
    sign_duration = perf_secp256k1_verify(this, secp256k1_sig_out, dataset, sk);
    cout << "Verified " << iteration * dataset_size << " messages, used: " << sign_duration<< " milliseconds" << endl;

    displayTitle("Multi Thread Perf for SECP256K1(bitcoin)");
    multi_thread_secp256k1_perf(this);

    free_random_dataset(secp256k1_sig_out);

    displayTitle("RSA(openssl) Basic Test");
    rsa_sign_verify();
    cout<<"Success"<<endl; // If failed, the code will be coredumped due to assert

    displayTitle("RSA(openssl) Perf Test");
    auto rsa_sig_ret = allocate_sig_msg_buf(512-dataset_vector_size);
    EVP_PKEY *ppkey= rsa_generate_keypair();
    sign_duration = perf_rsa_sign(rsa_sig_ret, dataset, ppkey);
    cout << "Signed " << iteration * dataset_size << " messages, used: " << sign_duration<< " milliseconds" << endl;
    sign_duration = perf_rsa_verify(rsa_sig_ret, dataset, ppkey);
    cout << "Signed " << iteration * dataset_size << " messages, used: " << sign_duration<< " milliseconds" << endl;

    displayTitle("Multi Thread Perf for RSA(openssl)");
    multi_thread_rsa_perf();

    rsa_free_keypair(ppkey);
    free_random_dataset(rsa_sig_ret);

    displayTitle("ED25519(naci) Basic Test");
    ed25519_basic_test();

    displayTitle("ED25519(naci) Perf Test");
    long sign_d = 0;
    long verify_d = 0;
    ed25519_perf_test(dataset, &sign_d, &verify_d);
    cout << "Signed " << iteration * dataset_size << " messages, used: " <<sign_d<< " milliseconds" << endl;
    cout << "Signed " << iteration * dataset_size << " messages, used: " <<verify_d<< " milliseconds" << endl;


    displayTitle("Multi Thread Perf for ED25519(naci)");
    multi_thread_ed25519_perf();

    displayTitle("ED22519(sodium) Perf Test");
    //1. Generate the dataset
    auto sig_ret = allocate_sig_msg_buf(crypto_sign_BYTES);
    crypto_sign_keypair(pk, sk);

    sign_duration = perf_crypto_sign(dataset, sk, sig_ret);
    cout << "Signed " << iteration * dataset_size << " messages, used: " << sign_duration<< " milliseconds" << endl;
    auto verify_duaration = perf_crypto_verify(sig_ret, pk);
    cout << "Verified " << iteration * dataset_size << " messages, used: " << verify_duaration<< " milliseconds" << endl;
    free_random_dataset(sig_ret);

    displayTitle("Multi Thread Perf for ED25519(sodium)");
    multi_thread_sig_perf();

    free_random_dataset(dataset);
}

crypto_perf::crypto_perf() {
    auto ret = sodium_init();
    assert(ret == 0);

    this->secp256k1_context1 = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
    assert(this->secp256k1_context1);

    // Rsa part
    ERR_load_crypto_strings();
    OPENSSL_add_all_algorithms_conf();
    OPENSSL_config(nullptr);
}


crypto_perf::~crypto_perf() {
    secp256k1_context_destroy(this->secp256k1_context1);

    //rsa part
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}