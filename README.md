[![CircleCI](https://circleci.com/gh/solarwinds/docker-plugin-papertail/tree/master.svg?style=svg&circle-token=3525100eff1bfced65f4c7ea77b81c14798a56a0)](https://circleci.com/gh/solarwinds/docker-plugin-papertail/tree/master)
<p align="center"><strong>NOTE</strong>: this is considered <strong>EXPERIMENTAL</strong> and is not yet recommended for production systems.</p>

# docker-plugin-papertail

This is a plugin for Docker to both send logs to and read logs from [Papertrail](https://papertrailapp.com)

**What is it?**
-----------

Once configured, it will send your Docker logs to Papertrail, buffer logs in the event of network disconnect as well as enable reading of remote logs from Papertrail through `docker logs` CLI.

**Why not the docker syslog driver?**
---------------------------------

 - This plugin adds little resilience. The data is persisted until it is sent to Papertrail.
 - Logs can be read from papertrail using docker logs. It also supports docker logs follow and tail options.

**How to use it?**
--------------

Prerequisites:

 - You will need a papertrail account. 
 - After you setup an account, you can grab the url to send logs to and the paper trail token. 
 - You should have docker installed on your machine (preferably docker version 1.17+)


Install the plugin:

    docker plugin install solarwinds/papertrail-plugin


----------


The plugin needs to use the host network for sending logs to paper trail. Please accept the permission.
 

    Plugin "solarwinds/papertrail-plugin" is requesting the following privileges:
     - network: [host]
    Do you grant the above permissions? [y/N] y


----------


Once installed, we need to configure docker to use the plugin.

Configuration options available are:
- papertrail-url: This is the papertrail url to send the logs to
- papertrail-token: The papertrail token used to fetch the logs
- papertrail-log-retention: Max duration for which the logs will be persisted in the event of the service not being reachable. Examples of accepted values: 24h, 10m, 20s, etc. The default value is 24h. 
- papertrail-max-diskusage: Max disk usage in percentage for persisting logs beyond which older logs will be discarded. For example: 5, 10, 12, etc. The default value is 5.


If you want to configure a specific container to use the driver, you can use the "--log-driver" and "--log-opt" options to `docker run` like this example below:

    docker run --rm --log-driver solarwinds/papertrail-plugin --log-opt papertrail-url=logsX.papertrailapp.com:XXXXX \
        --log-opt papertrail-token=adbdyxendkkxk ubuntu bash -c 'while true; do date +%s%N | sha256sum | base64 | head -c 32 ; echo " - Hello world"; sleep 10; done'


----------


To configure the Docker daemon to default to this logging driver, set the value of log-driver to "solarwinds/papertrail-plugin" of the logging driver in the daemon.json file, which is located in /etc/docker/ on Linux hosts or C:\ProgramData\docker\config\ on Windows server hosts. The following example explicitly sets the default logging driver to solarwinds/papertrail-plugin:

    {
      "log-driver": "solarwinds/papertrail-plugin",
      "log-opts": {
        "papertrail-url": "logsX.papertrailapp.com:XXXXX",
        "papertrail-token": "adbdyxendkkxk",
        "papertrail-log-retention": "4h",
        "papertrail-max-diskusage": "10"
      }
    }


----------
For viewing the logs:

    docker logs "container name"


----------


Tail the logs:

    docker logs -f "container name"


----------


Only view the last N lines:

    docker logs --tail N "container name"


----------


Start tailing from the last N lines:

    docker logs --tail N -f "container name"


----------

# Questions/Comments?
Please [open an issue](https://github.com/solarwinds/prometheus2appoptics/issues/new), we'd love to hear from you. As a SolarWinds Innovation Project, this adapter is supported in a best-effort fashion.

