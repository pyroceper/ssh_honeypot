#ifndef AUTH_H
#define AUTH_H

#include <iostream>
#include <string>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

namespace ssh 
{
    static int check_creds(const std::string &user, const std::string &passwd)
    {
        if(user == "root" && passwd == "toor")
        {
            return 1;
        }
        return 0;
    }

    static int authenticate(ssh_session session)
    {
        ssh_message message;

        do{
            message = ssh_message_get(session);
            if(!message)
                break;
            switch(ssh_message_type(message))
            {
                case SSH_REQUEST_AUTH:
                    switch(ssh_message_subtype(message))
                    {
                        case SSH_AUTH_METHOD_PASSWORD:
                        {
                            // std::cout << "[debug] user wants to use auth and passwd " << ssh_message_auth_user(message) << 
                            //             ssh_message_auth_password(message) << std::endl;
                            std::string user(ssh_message_auth_user(message));
                            std::string passwd(ssh_message_auth_password(message));
                            if(check_creds(user, passwd))
                            {
                                ssh_message_auth_reply_success(message, 0);
                                ssh_message_free(message);
                                return 1;
                            }
                            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_INTERACTIVE);

                            //when auth fails send this
                            ssh_message_reply_default(message);
                            break;
                        }

                        case SSH_AUTH_METHOD_NONE:
                        default:
                        {
                            // std::cout << "[debug] no authenication mode used by user " << ssh_message_auth_user(message) << 
                            //         ssh_message_auth_password(message) << std::endl;
                            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_INTERACTIVE);
                            ssh_message_reply_default(message);
                            break;
                        }    
                    }
                break;
                default:
                    ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_INTERACTIVE);
                    ssh_message_reply_default(message);
            }
            ssh_message_free(message);
        }while(1);

        return 0;
    }
}

#endif