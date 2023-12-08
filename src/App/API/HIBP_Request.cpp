#include"HIBP_Request.h"


CURL* GetCurlInstance() {
    
    CURL* curl;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    return curl;
}
 
size_t WriteCallback(void* contents, size_t size, size_t str_len, std::string* output) {
    size_t total_size = size * str_len;
    output->append((char*)contents, total_size);
    return total_size;
}

void SetCurlOptions(CURL* curl, const char* URL, std::string* response) {

    curl_easy_setopt(curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
}

std::string FetchData(std::string URL) {

    CURL* curl = GetCurlInstance();
    CURLcode err;
    std::string response = "";

    if (curl) {
        SetCurlOptions(curl, URL.c_str(), &response);
        err = curl_easy_perform(curl);
        if (err != CURLE_OK) {
            printf("[ERROR] can't fetch data from API source.\n");
        } 
        curl_easy_cleanup(curl);
    }

    return response;
}