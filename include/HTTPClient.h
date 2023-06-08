#include <stdio.h>
#include <string>
#include <curl/curl.h>
#include <iostream>
#include <fstream>

size_t write_to_string(void* ptr, size_t size, size_t count, void* stream) {
    ((std::string*)stream)->append((char*)ptr, 0, size * count);
    return size * count;
}

std::string GetAnalysisFromFile(std::string filePath) {

    std::string url = "https://www.virustotal.com/api/v3/files";
    std::string fileName = filePath.substr(filePath.find_last_of("/") + 1); //TODO fail safely
    std::cout << fileName;
    std::string apikey;
    std::ifstream readKeyFromFile("apikey.txt"); //TODO fail safely
    getline(readKeyFromFile, apikey);
    readKeyFromFile.close();

    CURL* curl;
    CURLcode res;

    curl_mime* form = NULL;
    curl_mimepart* field = NULL;
    struct curl_slist* headerlist = NULL;

    curl = curl_easy_init();

    if (curl) {
        /* Create the form */
        form = curl_mime_init(curl);

        /* Fill in the file upload field */
        field = curl_mime_addpart(form);
        curl_mime_name(field, "file");
        curl_mime_filedata(field, filePath.c_str());

        /* add apikey to headers */
        headerlist = curl_slist_append(headerlist, apikey.c_str());

        /* what URL that receives this POST */
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        /* verbose mode */
        //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);
        std::string response;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_string);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        /* Run file POST */
        res = curl_easy_perform(curl);

        /* Parse analysis link (if any) and perform GET on it */
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        }
        else if (response.length() <= 0) {
            fprintf(stderr, "write response to body failed: %s\n",
                curl_easy_strerror(res));
        }
        else {
            //TODO fail safely
            std::string link = response.substr(response.find("self") + 8); //API response has format - "self": "https: ... - don't want to parse the whole JSON just for this
            link = link.substr(0, link.find("\""));

            curl_easy_reset(curl);
            curl_easy_setopt(curl, CURLOPT_URL, link.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_string);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            res = curl_easy_perform(curl);

            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
            }
            else if (response.length() <= 0) {
                fprintf(stderr, "write response to body failed: %s\n",
                    curl_easy_strerror(res));
            }
            else {

                curl_easy_cleanup(curl);
                curl_mime_free(form);
                curl_slist_free_all(headerlist);

                return response;
            }

        }

        /* always cleanup */
        curl_easy_cleanup(curl);

        /* then cleanup the form */
        curl_mime_free(form);

        /* free slist */
        curl_slist_free_all(headerlist);

        return ""; //TODO fail safely
    }
}

//TODO implement GetAnalysisFromHash function