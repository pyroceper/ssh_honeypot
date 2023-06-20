#ifndef INOTIFY_H
#define INOTIFY_H

#include "HTTPClient.h"
#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/inotify.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024*(EVENT_SIZE + 16))

namespace inotify
{
    struct MonitorFs 
    {
        int fd;
        int wd;
        int child_pid;
        bool is_running;
    };
    
    void monitor_filesystem(MonitorFs *fs, const std::string path)
    {
        int len, status, i = 0;

        char buffer[BUF_LEN];

        fs->fd = inotify_init();
        if(fs->fd < 0)
        {
            printf("fd error\n");
        }

        fs->wd = inotify_add_watch(fs->fd, path.c_str(), IN_MODIFY | IN_CREATE | IN_DELETE);

 
        fs->is_running = true;

        int id {};
        while(fs->is_running)
        {
            id = waitpid(fs->child_pid, &status, WNOHANG);
            if(id == 0)
            {
                i = 0;    
                len = read(fs->fd, buffer, BUF_LEN);
                if(len < 0)
                {
                    printf("read\n");
                }

                while(i < len)
                {
                    struct inotify_event *event = (struct inotify_event *) &buffer[i];
                    if(event->len)
                    {
                        if(event->mask & IN_CREATE)
                        {
                            if(event->mask & IN_ISDIR)
                            {
                                printf("dir %s was created\n", event->name);
                            }
                            else
                            {
                                printf("file %s was created\n", event->name);
                                std::string temp_file(event->name);
                                std::string test_file = path + "/" + temp_file;
                                printf("sending %s to virus_total\n", test_file.c_str());
                                std::cout << GetAnalysisFromFile(test_file);
                                std::string filename(event->name);
                                filename = "logs/" + filename + "_vt_log.json";
                                std::ofstream logfile(filename);
                                if(logfile.is_open())
                                {
                                    logfile << GetAnalysisFromFile(test_file);
                                }
                                logfile.close();
                            }   
                        }
                        else if(event->mask & IN_DELETE)
                        {
                            if(event->mask & IN_ISDIR)
                            {
                                printf("dir %s was deleted\n", event->name);
                            }
                            else
                                printf("file %s was deleted\n", event->name);
                        }
                        else if(event->mask & IN_MODIFY)
                        {
                            if(event->mask & IN_ISDIR)
                            {
                                printf("dir %s was modified\n", event->name);
                            }
                            else
                            {
                                printf("file %s was modified\n", event->name);
                                std::string temp_file(event->name);
                                std::string test_file = path + "/" + temp_file;
                                printf("sending %s to virus_total\n", test_file.c_str());
                                GetAnalysisFromFile(test_file);
                                std::cout << GetAnalysisFromFile(test_file);
                            }
                        }
                    }
                    i += EVENT_SIZE + event->len;
                }
            }
            else if(id == -1)
            {
                printf("Error ssh server\n");
                fs->is_running = false;
            }
            else 
            {
                if(WIFEXITED(status))
                {
                    exit(1);
                    fs->is_running = false;
                }
            }
        }

        (void) inotify_rm_watch(fs->fd, fs->wd);
        (void) close(fs->fd); 
    }
}


#endif