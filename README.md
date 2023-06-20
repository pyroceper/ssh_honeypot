# SSH Honeypot (INSE 6630 capstone project)

Run the setup script first to setup the environment
```
# ./setup.sh
......
```

Once the setup completes run `make` to compile any changes

```
$ make
```

To run the app, simply use `make run`

```
$ make run
```

The `config.json` can use be used to edit the configuration of the honeypot.
```
{
    "port" : 2222, // port to listen 
    "path" : "fs", // directory to monitor 
    "banner" : "SSH honeypot", // custom banner 
    "fakeroot" : 1, // enables fakeroot, any other value disables it
    "API" : "x-apikey: <key>" // dont forget to add your virus total API key here and in apikey.txt!
}
```

All the activities of the user interacting with the server are stored in the `log` directory

## The Team

| Name      | Student ID |
| ----------- | ----------- |
| Fatimah Bayanooni   | 40243704       |
| Rahma Tabakh   |  40218780        |
| Melika Khani | 40199470 |
| Aditya Shenoy Uppinangady | 40216499 |
| Gabriel Amboss Pinto | 40165876 |
| Bashar Kaddoura | 40157014 |

### Primary Programmers
| Name      | Github ID |
| ----------- | ----------- |
| Aditya Shenoy Uppinangady  | pyroceper       |
| Gabriel Amboss Pinto  |  gabrielamboss         |



