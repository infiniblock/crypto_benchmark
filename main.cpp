#include <iostream>
#include "crypto_perf.hpp"
#include "hash_perf.hpp"
#include "compress_perf.hpp"
#include <boost/program_options.hpp>


int main(int argc, char ** argv) {

    boost::program_options::options_description desc("Crypto/Hash");

    desc.add_options()
            ("crypto", "Do crypto benchmark")
            ("compress", "Do compress benchmark")
            ("hash", "Do hash benchmark");

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);

    boost::program_options::notify(vm);

    if (vm.count("crypto")) {
        auto cp = crypto_perf();
        cp.run();
    }

    if (vm.count("hash")) {
        auto hp = hash_perf();
        hp.run();
    }

    if (vm.count("compress")) {
        compress_perf().run();
    }

    return 0;
}