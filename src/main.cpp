#include "config.h"
#include "ssh.h"
#include "inotify.h"
#include "HTTPClient.h"

int main(int argc, char *argv[])
{
    // std::cout << GetAnalysisFromFile("./cmds.txt");
    config::Config app_config {};

    config::read_config(&app_config);

    inotify::MonitorFs fs {};

    int rs {};
    fs.child_pid = fork();
    if(fs.child_pid == 0)
    {
        rs = ssh::ssh_server(&app_config);
        if(rs == 1)
            exit(1);
    }
    else 
    {
        inotify::monitor_filesystem(&fs, app_config.path);
        exit(1);
    }
    return 0;
}