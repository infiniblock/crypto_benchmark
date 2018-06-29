#pragma  once
#include <iostream>

namespace display {
using namespace std;

template <class T>
void displayNumbers(T data, int dataNumber) 
{
    // Display the numbers
    for (int i = 0; i < dataNumber; i++) {
        if (i == 0) {
            cout << "The numbers are: "; 
        }
        cout<< data[i]; 

        if (i == dataNumber - 1) {
            cout << endl;
        } else {
            cout << " ";
        }
    }

    return;
}
void displayTitle(string const& title);
void printCharInHex(unsigned char*, size_t);
}
