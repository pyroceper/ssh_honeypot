#ifndef CONFIG_H
#define CONFIG_H

#include <iostream>
#include <string>
#include <fstream>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace config
{
    struct Config
    {
        int port;
        std::string path;
        bool fakeroot;
        std::string banner;
    };
    void read_config(Config *app_config)
    {
        std::ifstream config_file("config.json");

        json data = json::parse(config_file);

        if(config_file.is_open())
        {
            app_config->port = data["port"];
            app_config->path = data["path"];
            app_config->banner = data["banner"];
            if(data["fakeroot"] == 1)
                app_config->fakeroot = true;
            else 
                app_config->fakeroot = false;
        }
        config_file.close();
    }
}

#endif 