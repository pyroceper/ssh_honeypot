#include "HTTPClient.h"

//Usage example, can delete
//Depends on "apikey.txt" and data file being available
//apikey.txt must be on same directory and have format "x-apikey: <APIKEY>" (without quotes)
//Data file path is passed on function - can be full or relative path (if on the same directory)
int main(void)
{
    //std::cout << GetAnalysisFromFile("eicar.txt");

    //std::cout << GetAnalysisFromHash("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"); //EICAR test file SHA256 hash

    std::cout << GetAnalysisFromUrl("google.com");

    return 0;
}