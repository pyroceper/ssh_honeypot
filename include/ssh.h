#ifndef SSH_H
#define SSH_H 

#include "config.h"
#include "authenticate.h"
#include "remote_shell.h"

#define KEYS_FOLDER "keys/"

namespace ssh 
{
    int ssh_server(config::Config *cfg)
    {
        ssh_session session;
        ssh_bind bind;
        ssh_message message;
        ssh_channel chan = 0;
        int auth, port, shell, rc;
        auth = shell = 0;
        port = cfg->port;

        rc = ssh_init();
        if(rc < 0)
        {
            std::cerr << "ssh_init failed\n";
            return 1;
        }

        bind = ssh_bind_new();
        if(bind == nullptr)
        {
            std::cerr << "Error listening on socket: " << ssh_get_error(bind) << std::endl;
            ssh_finalize();
            return 1;
        }

        // ssh_bind_options_set(bind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "4"); // 4 -> SSH_LOG_FUNCTIONS
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT, &port);
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BANNER, cfg->banner.c_str());
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");

        if(ssh_bind_listen(bind) < 0)
        {
            std::cerr << "Error listening on port: "<< ssh_get_error(bind) << std::endl;
            ssh_bind_free(bind);
            ssh_finalize();
            return 1;
        }

        // while(1)
        // {
            session = ssh_new();

            rc = ssh_bind_accept(bind, session);
            if(rc == SSH_ERROR)
            {
                std::cerr << "Error accepting connection: "<< ssh_get_error(bind) << std::endl;
                return 1;
            }

            if(ssh_handle_key_exchange(session))
            {
                std::cerr << "ssh_handle_key_exchange: "<< ssh_get_error(session) << std::endl;
                return 1;
            }

            auth = authenticate(session);
            if(!auth)
            {
                std::cerr << "Authenication error " << ssh_get_error(session) << std::endl;
                ssh_disconnect(session);
                ssh_finalize();
                return 1;
            }
            else 
                std::cout << "Authenication successful\n";

            do{
                message = ssh_message_get(session);
                if(message)
                {
                    if(ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN && 
                        ssh_message_subtype(message) == SSH_CHANNEL_SESSION)
                    {
                        chan = ssh_message_channel_request_open_reply_accept(message);
                        ssh_message_free(message);
                        break;
                    }
                    else 
                    {
                        ssh_message_reply_default(message);
                        ssh_message_free(message);
                    }
                }
                else 
                    break;
            }while(!chan);

            if(!chan)
            {
                std::cerr << "Error: Client did not request for a channel " << ssh_get_error(session);
                ssh_finalize();
                return 1;
            }

            do{
                message = ssh_message_get(session);
                if(message != nullptr)
                {
                    if(ssh_message_type(message) == SSH_REQUEST_CHANNEL)
                    {
                        if(ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SHELL)
                        {
                            shell = 1;
                            ssh_message_channel_request_reply_success(message);
                            ssh_message_free(message);
                            break;
                        }
                        else if(ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_PTY)
                        {
                            ssh_message_channel_request_reply_success(message);
                            ssh_message_free(message);
                            continue;
                        }
                    }
                    ssh_message_reply_default(message);
                    ssh_message_free(message);
                }
                else 
                    break;
            }while(!shell);

            if(!shell)
            {
                std::cerr << "Error: No shell requested by the user " << ssh_get_error(session);
                ssh_finalize();
                return 1;
            }

            std::cout << "Spawning shell...\n";

            main_loop(chan, cfg);

            ssh_disconnect(session);
            ssh_bind_free(bind);
    // }

        ssh_finalize();
        return 0;
    }
}


#endif