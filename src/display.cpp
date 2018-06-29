//
// Created by jinjun on 18-5-30.
//

#include "display.hpp"
#include <iostream>
#include <cassert>
#include <boost/format.hpp>

namespace display {

    const int HeaderLength = 80;
    using namespace std;
    using boost::format;

    void displayTitle(string const& title) {
        // Calculate the total length

        assert(title.length() <= HeaderLength);
        long left_label_number = (HeaderLength - title.length()) / 2;
        long right_label_number = HeaderLength - title.length() - left_label_number;
        assert(right_label_number >= 0);

        string header;

        for (int i= 0; i < left_label_number; i ++) {
            header.append("=");
        }

        header.append(title);

        for (int i= 0; i < right_label_number; i ++) {
            header.append("=");
        }

        cout << header << endl;
    }

    void printCharInHex(unsigned char* data, size_t len) {
        cout<<"0x";
        for (int i=0; i < len; i++ ) {
            cout<<format("%02x")%(unsigned int)data[len-i-1];
        }
        return;
    }

}

