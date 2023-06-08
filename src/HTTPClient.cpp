#include "HTTPClient.h"

//Usage example, can delete
//Depends on "apikey.txt" and data file being available
//apikey.txt must be on same directory and have format "x-apikey: <APIKEY>" (without quotes)
//Data file path is passed on function - can be full or relative path (if on the same directory)
int main(void)
{
    std::cout << GetAnalysisFromFile("eicar.txt");

    return 0;
}