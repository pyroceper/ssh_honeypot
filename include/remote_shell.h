#ifndef REMOTE_SHELL_H
#define REMOTE_SHELL_H

#include <iostream>
#include <string>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <poll.h>
#include <pty.h>

namespace ssh
{
    static int copy_fd_to_chan(socket_t fd, int revents, void *userdata)
    {
        ssh_channel chan = (ssh_channel)userdata;
        char buf[2048];
        int sz = 0;

        if(!chan)
        {
            close(fd);
            return -1;
        }

        if(revents & POLLIN)
        {
            sz = read(fd, buf, 2048);
            if(sz > 0)
            {
                ssh_channel_write(chan, buf, sz);
            }
        }

        if(revents & POLLHUP)
        {
            ssh_channel_close(chan);
            sz = -1;
        }
        return sz;
    }

    static int copy_chan_to_fd(ssh_session session, ssh_channel channel, void *data,
        uint32_t len, int is_stderr, void *userdata)
    {
        int fd = *(int*)userdata;
        int sz;
        (void)session;
        (void)channel;
        (void)is_stderr;

        sz = write(fd, data, len);
        return sz;
    }

    static void chan_close(ssh_session session, ssh_channel channel, void *userdata)
    {
        int fd = *(int*)userdata;
        (void)session;
        (void)channel;

        close(fd);
    }

    struct ssh_channel_callbacks_struct cb = {
        .userdata = nullptr,
        .channel_data_function = copy_chan_to_fd,
        .channel_eof_function = chan_close,
        .channel_close_function = chan_close,
    };


    static int main_loop(ssh_channel chan, config::Config *cfg)
    {
        ssh_session session = ssh_channel_get_session(chan);
        socket_t fd;

        struct termios *term = nullptr;
        struct winsize *win = nullptr;
        pid_t childpid;
        ssh_event event;

        short events;
        int rc;

        childpid = forkpty(&fd, nullptr, term, win);
        std::string shell_str {};
       
       
        if(childpid == 0)
        {
            if(cfg->fakeroot)
            {
                setenv("HISTFILE", "logs/cmds.txt", 1);
                //if(execl("/usr/bin/fakeroot", "/usr/bin/fakeroot", "/bin/bash", (char *)nullptr) == -1)
                if(execl("/bin/bash", "/bin/bash", "-c", "/usr/bin/fakeroot", (char *)nullptr) == -1)
                {
                    std::cerr << "execl error\n";
                    return -1;
                }
            }
            else 
            {
                setenv("HISTFILE", "logs/cmds.txt", 1);
                if(execl("/bin/bash", "/bin/bash", (char *)nullptr) == -1)
                {
                    std::cerr << "execl error\n";
                    return -1;
                }  
            }
            abort();
        }

        cb.userdata = &fd;
        ssh_callbacks_init(&cb);
        ssh_set_channel_callbacks(chan, &cb);

        events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

        event = ssh_event_new();
        if(event == nullptr)
        {
            std::cerr << "Error: Could not create event\n";
            return -1;
        }

        if(ssh_event_add_fd(event, fd, events, copy_fd_to_chan, chan) != SSH_OK)
        {
            std::cerr << "Error: Could not add fd to event\n";
            ssh_event_free(event);
            return -1;
        }

        if(ssh_event_add_session(event, session) != SSH_OK) 
        {
            std::cerr << "Could not add session to event\n";
            ssh_event_remove_fd(event, fd);
            ssh_event_free(event);
            return -1;
        }

        do{
            rc = ssh_event_dopoll(event, 1000);
            if(rc == SSH_ERROR)
            {
                std::cerr << "Error: " << ssh_get_error(session) << std::endl;
                ssh_event_free(event);
                ssh_disconnect(session);
                return -1;
            }

        }while(!ssh_channel_is_closed(chan));

        ssh_event_remove_fd(event, fd);
        ssh_event_remove_session(event, session);
        ssh_event_free(event);
        return 0;
    }
}

#endif 
