# crypto_benchmark
Crypto Benchmark for Signature and Hash 

# Test setup 

The following libs are evaluated:

- [libsodium](https://github.com/jedisct1/libsodium)
- [libsecp256k1](https://github.com/bitcoin-core/secp256k1)
- [ed25519](https://github.com/hyperledger/iroha-ed25519)
- [openssl](https://www.openssl.org/)
- [KCP](https://keccak.team/)

The reason we evaluate ed25519 is that, in theory ED25519 can be optimized  to high perf implementation. Foe details, please see this [paper](https://ed25519.cr.yp.to/ed25519-20110926.pdf).

KCP contains the latest HASH implementations, such as K12 and SHA3, They are candidates for  Infiniblock. 

# Test Environment

```apple js
jinjun@jinjun-virtual-machine:~/ws/crypto_benchmark/cmake-build-debug$ cat /proc/cpuinfo 
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 94
model name	: Intel(R) Core(TM) i7-6700HQ CPU @ 2.60GHz
stepping	: 3
microcode	: 0x33
cpu MHz		: 2592.080
cache size	: 6144 KB
physical id	: 0
siblings	: 1
core id		: 0
cpu cores	: 1
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 22
wp		: yes
```
 

# Test Results 

```apple js

=========================Secp256K1(bitcoin) Basic Test==========================
Success
==========================secp256k1(bitcoin) Perf Test==========================
Signed 1000 messages, used: 58 milliseconds
Verified 1000 messages, used: 77 milliseconds
====================Multi Thread Perf for SECP256K1(bitcoin)====================
In thread 0
Signed 1000 messages, used: 52 milliseconds
Verified 1000 messages, used: 74 milliseconds
In thread 3
Signed 1000 messages, used: 53 milliseconds
Verified 1000 messages, used: 72 milliseconds
In thread 1
Signed 1000 messages, used: 66 milliseconds
Verified 1000 messages, used: 84 milliseconds
In thread 2
Signed 1000 messages, used: 78 milliseconds
Verified 1000 messages, used: 89 milliseconds
============================RSA(openssl) Basic Test=============================
Success
=============================RSA(openssl) Perf Test=============================
Signed 1000 messages, used: 676 milliseconds
Signed 1000 messages, used: 22 milliseconds
=======================Multi Thread Perf for RSA(openssl)=======================
In thread 3
Signed 1000 messages, used: 765 milliseconds
Verified 1000 messages, used: 21 milliseconds
In thread 1
Signed 1000 messages, used: 759 milliseconds
Verified 1000 messages, used: 25 milliseconds
In thread 2
Signed 1000 messages, used: 728 milliseconds
Verified 1000 messages, used: 23 milliseconds
In thread 0
Signed 1000 messages, used: 734 milliseconds
Verified 1000 messages, used: 21 milliseconds
============================ED25519(naci) Basic Test============================
============================ED25519(naci) Perf Test=============================
Signed 1000 messages, used: 21 milliseconds
Signed 1000 messages, used: 60 milliseconds
======================Multi Thread Perf for ED25519(naci)=======================
In thread 0
Signed 1000 messages, used: 22 milliseconds
Verified 1000 messages, used: 60 milliseconds
In thread 1
Signed 1000 messages, used: 20 milliseconds
Verified 1000 messages, used: 67 milliseconds
In thread 3
Signed 1000 messages, used: 23 milliseconds
Verified 1000 messages, used: 77 milliseconds
In thread 2
Signed 1000 messages, used: 21 milliseconds
Verified 1000 messages, used: 89 milliseconds
===========================ED22519(sodium) Perf Test============================
Signed 1000 messages, used: 33 milliseconds
Verified 1000 messages, used: 73 milliseconds
=====================Multi Thread Perf for ED25519(sodium)======================
In thread 0
Signed 1000 messages, used: 27 milliseconds
Verified 1000 messages, used: 81 milliseconds
In thread 1
Signed 1000 messages, used: 36 milliseconds
Verified 1000 messages, used: 76 milliseconds
In thread 2
Signed 1000 messages, used: 35 milliseconds
Verified 1000 messages, used: 78 milliseconds
In thread 3
Signed 1000 messages, used: 41 milliseconds
Verified 1000 messages, used: 76 milliseconds
K12: Hash 1024M bytes data, used:955 milliseconds
SHA256: Hash 1024M bytes data, used:2674 milliseconds
SHA3: Hash 1024M bytes data, used:434 milliseconds
```

# Conclusion 

As the results show, we will use the **ED25519** as Infiniblock sign/verify algorithm, use the **SHA3** as the hash algorithm.

As to compress, since current compress algorithm are uesless to signature, which is the main part of the transaction, do we really need compress? 

The answer is NO!