#ifndef HIBP
#define HIBP

#include <curl/curl.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <fstream>
 

static std::string API_URL = "https://api.pwnedpasswords.com/range/";

std::string FetchData(std::string);

#endif