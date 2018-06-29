//
// Created by jinjun on 18-6-29.
//

#ifndef CRYPTO_SELECTION_ED25519_PERF_HPP
#define CRYPTO_SELECTION_ED25519_PERF_HPP

extern void ed25519_basic_test();
extern void ed25519_perf_test(uint8_t **dataset, long *sign_duaration, long* verify_duaration);

extern void ed25519_perf_thread(int i);
#endif //CRYPTO_SELECTION_ED25519_PERF_HPP
