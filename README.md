# StayRTR

![animated stayrtr logo](stayrtr.gif)

[![Docker Pulls](https://img.shields.io/docker/pulls/rpki/stayrtr.svg)](https://hub.docker.com/r/rpki/stayrtr)

<a href="https://repology.org/project/stayrtr/versions">
    <img src="https://repology.org/badge/vertical-allrepos/stayrtr.svg" alt="Packaging status" align="right">
</a>

StayRTR is an open-source implementation of RPKI-to-Router protocol (RFC 6810, RFC 8210, RFC 8210bis); based on GoRTR using the [the Go Programming Language](http://golang.org/).

* `/lib` contains a library to create your own server and client.
* `/prefixfile` contains the structure of a JSON export file and signing capabilities.
* `/cmd/stayrtr/stayrtr.go` is a simple implementation that fetches a list and offers it to a router.
* `/cmd/rtrdump/rtrdump.go` allows copying the PDUs sent by a RTR server as a JSON file.
* `/cmd/rtrmon/rtrmon.go` compare and monitor two RTR servers (using RTR and/or JSON), outputs diff and Prometheus metrics.

## Disclaimer

_This software comes with no warranty._

## Sponsors

The StayRTR project was built on contributions of money and time.
Special thanks for support to the Route Server Support Foundation [RSSF](https://www.rssf.nl), [Internet Society](https://www.internetsociety.org/) and [PCCW Global](https://www.pccwglobal.com/).

## Features of the server

* Dissemination of validated ROA, BGPsec, and ASPA payloads
* Refreshes a JSON list of prefixes
* Automatic expiration of outdated information (when using JSON produced by [rpki-client](https://www.rpki-client.org))
* Prometheus metrics
* TLS
* SSH

## Features of the extractor

* Generate a list of prefixes received via RTR into a JSON file
* Lightweight
* TLS
* SSH

## Features of the API

* Protocol v0 of [RFC6810](https://tools.ietf.org/html/rfc6810)
* Protocol v1 of [RFC8210](https://tools.ietf.org/html/rfc8210)
* Protocol v2 of [draft-ietf-sidrops-8210bis-23](https://tools.ietf.org/html/draft-ietf-sidrops-8210bis-23)
* Event-driven API
* TLS
* SSH

## To start developing

You need a working [Go environment](https://golang.org/doc/install) (1.24 or newer).
This project also uses [Go Modules](https://github.com/golang/go/wiki/Modules).

```bash
$ git clone git@github.com:bgp/stayrtr.git && cd stayrtr
$ go build cmd/stayrtr/stayrtr.go
```

## With Docker

If you do not want to use Docker, please go to the next section.

If you have **Docker**, you can start StayRTR with `docker run -ti -p 8082:8082 rpki/stayrtr` someday when it has been built.

You can now use any CLI attributes as long as they are after the image name:

```bash
$ docker run -ti -p 8083:8083 rpki/stayrtr -bind :8083
```

If you want to build your own image of StayRTR:

```bash
$ docker build -t mystayrtr -f Dockerfile.stayrtr.prod .
$ docker run -ti mystayrtr -h
```

It will download the code from GitHub and compile it with Go and also generate an ECDSA key for SSH.

Please note: if you plan to use SSH with the default container (`rpki/stayrtr`),
replace the key `private.pem` since it is a testing key that has been published.
An example is given below:

```bash
$ docker run -ti -v $PWD/mynewkey.pem:/private.pem rpki/stayrtr -ssh.bind :8083
```

## Install it

There are a few solutions to install it.

Go can directly fetch it from the source

```bash
$ go get github.com/bgp/stayrtr/cmd/stayrtr
```

You can use the Makefile (by default it will be compiled for Linux, add `GOOS=darwin` for Mac)

```bash
$ make build-stayrtr
```

The compiled file will be in `/dist`.

Or you can use a tarball file from the [Releases page](https://github.com/bgp/stayrtr/releases):

## Run it

Once you have a binary:

```bash
$ ./stayrtr -tls.bind 127.0.0.1:8282
```

## Package it

If you want to package it (deb/rpm), you can use the pre-built docker-compose file.

```bash
$ docker-compose -f docker-compose-pkg.yml up
```

You can find both files in the `dist/` directory.

### Usage with a proxy

This was tested with a basic Squid proxy. The `User-Agent` header is passed
in the CONNECT.

You have to export the following two variables in order for StayRTR to use the proxy.

```
export HTTP_PROXY=schema://host:port
export HTTPS_PROXY=schema://host:port
```

### With SSL

You can run StayRTR and listen for TLS connections only (just pass `-bind ""`).

First, you will have to create a SSL certificate.

```bash
$ openssl ecparam -genkey -name prime256v1 -noout -outform pem > private.pem
$ openssl req -new -x509 -key private.pem -out server.pem
```

Then, you have to run

```bash
$ ./stayrtr -tls.bind :8282 -tls.key private.pem -tls.cert server.pem
```

### With SSH

You can run StayRTR and listen for SSH connections only (just pass `-bind ""`).

You will have to create an ECDSA key. You can use the following command:

```bash
$ openssl ecparam -genkey -name prime256v1 -noout -outform pem > private.pem
```

Then you can start:

```bash
$ ./stayrtr -ssh.bind :8282 -ssh.key private.pem -bind ""
```

By default, there is no authentication.

You can use password and key authentication:

For example, to configure user **rpki** and password **rpki**:

```bash
$ ./stayrtr -ssh.bind :8282 -ssh.key private.pem -ssh.method.password=true -ssh.auth.user rpki -ssh.auth.password rpki -bind ""
```

And to configure a bypass for every SSH key:

```bash
$ ./stayrtr -ssh.bind :8282 -ssh.key private.pem -ssh.method.key=true -ssh.auth.key.bypass=true -bind ""
```

## Configure filters and overrides (SLURM)

StayRTR supports SLURM configuration files ([RFC8416](https://tools.ietf.org/html/rfc8416)).

Create a json file (`slurm.json`):

```
{
    "slurmVersion": 1,
    "validationOutputFilters": {
     "prefixFilters": [
       {
        "prefix": "10.0.0.0/8",
        "comment": "Everything inside will be removed"
       },
       {
        "asn": 65001,
       },
       {
        "asn": 65002,
        "prefix": "192.168.0.0/24",
       },
     ],
     "bgpsecFilters": []
    },
    "locallyAddedAssertions": {
     "prefixAssertions": [
       {
        "asn": 65001,
        "prefix": "2001:db8::/32",
        "maxPrefixLength": 48,
        "comment": "Manual add"
       }
     ],
     "bgpsecAssertions": [
     ]
    }
  }
```

When starting StayRTR, add the `-slurm ./slurm.json` argument.

The log should display something similar to the following:

```
INFO[0001] Slurm filtering: 112214 kept, 159 removed, 1 asserted
INFO[0002] New update (112215 uniques, 112215 total prefixes).
```

For instance, if the original JSON fetched contains the VRP: `10.0.0.0/24-24 AS65001`,
it will be removed.

The JSON exported by StayRTR will contain the overrides and the file can be signed again.
Others StayRTR can be configured to fetch the VRPs from the filtering StayRTR:
the operator manages one SLURM file on a leader StayRTR.

## Debug the content

You can check the content provided over RTR with rtrdump tool

```bash
$ ./rtrdump -connect 127.0.0.1:8282 -file debug.json
```

You can also fetch the re-generated JSON from the `-export.path` endpoint (default: `http://localhost:9847/rpki.json`)

## Monitoring rtr and JSON endpoints

With `rtrmon` you can monitor the difference between rtr and/or JSON endpoints.
You can use this to, for example, track that your StayRTR instance is still in
sync with your RP instance. Or to track that multiple RP instances are in sync.

If your CA software has an endpoint that exposes objects in the standard JSON
format, you can even make sure that the objects that your CA software should
generate actually are visible to RPs, to monitor the full cycle.

```
$ ./rtrmon \
  -primary.host tcp://rtr.rpki.cloudflare.com:8282 \
  -secondary.host https://console.rpki-client.org/rpki.json \
  -secondary.refresh 30s \
  -primary.refresh 30s
```

rtrmon has two endpoints:
  * `/metrics`: for prometheus metrics
  * `/diff.json` (default, can be overridden by the `-file` flag): for a JSON file containing the difference between sources

### diff

The `diff.json` endpoint contains four keys.

  * `metadata-primary`: configuration of the primary source
  * `metadata-secondary`: configuration of the secondary source
  * `only-primary`: objects in the primary source but not in the secondary source.
  * `only-secondary`: objects in the secondary source but not in the primary source.

### Metrics
By default the Prometheus endpoint is on `http://[host]:9866/metrics`.
Among others, this endpoint contains the following metrics:

  * `rpki_vrps`: Current number of VRPS and current difference between the primary and secondary.
  * `rtr_serial`: Serial of the rtr session (when applicable).
  * `rtr_session`: Session ID of the RTR session.
  * `rtr_state`: State of the rtr session (up/down).
  * `update`: Timestamp of the last update.
  * `vrp_diff`: The number of VRPs which were seen in `lhs` at least `visibility_seconds` ago not in `rhs`.

Using these metrics you can visualise or alert on, for example:

  * Unexpected behaviour
    * Did the number of VRPs drop more than 10% compared to the 24h average?
  * Liveliness
    * Is the RTR serial increasing?
    * Is rtrmon still getting updates?
  * Convergence
    * Do both my RP instances see the same objects eventually?
    * Are objects first visible in the JSON `difference` (e.g. 1706) seconds ago visible in RTR?

When the objects are not converging, the `diff.json` endpoint may help while investigating the issues.

### Data sources

Use your own validator, as long as the JSON source follows the following schema:

```
{
  "roas": [
    {
      "prefix": "10.0.0.0/24",
      "maxLength": 24,
      "asn": 65001
    },
    ...
  ]
}
```

* **Third-party JSON formatted VRP exports:**
  * [console.rpki-client.org](https://console.rpki-client.org/rpki.json) (default, based on OpenBSD's `rpki-client`)
  * [NTT](https://rpki.gin.ntt.net/api/export.json) (based on OpenBSD's `rpki-client`)

By default, the session ID will be randomly generated. The serial will start at zero.

Make sure the refresh rate of StayRTR is more frequent than the refresh rate of the JSON.

## Configurations

### Compatibility matrix

A simple comparison between software and devices.
Implementations on versions may vary.

| Device/software | Plaintext | TLS | SSH | Notes             |
| --------------- | --------- | --- | --- | ----------------- |
| RTRdump         | Yes       | Yes | Yes |                   |
| RTRlib          | Yes       | No  | Yes | Only SSH key      |
| Juniper         | Yes       | No  | No  |                   |
| Cisco           | Yes       | No  | Yes | Only SSH password |
| Nokia           | Yes       | No  | No  |                   |
| Arista          | Yes       | No  | No  |                   |
| FRRouting       | Yes       | No  | Yes | Only SSH key      |
| Bird2           | Yes       | No  | Yes | Only SSH key      |
| Quagga          | Yes       | No  | No  |                   |
| OpenBGPD        | Yes       | No  | No  |                   |

### Configure on Juniper

Configure a session to the RTR server (assuming it runs on `192.168.1.100:8282`)

```
louis@router> show configuration routing-options validation
group TEST-RPKI {
    session 192.168.1.100 {
        port 8282;
    }
}
```

Add policies to validate or invalidate prefixes

```
louis@router> show configuration policy-options policy-statement STATEMENT-EXAMPLE
term RPKI-TEST-VAL {
    from {
        protocol bgp;
        validation-database valid;
    }
    then {
        validation-state valid;
        next term;
    }
}
term RPKI-TEST-INV {
    from {
        protocol bgp;
        validation-database invalid;
    }
    then {
        validation-state invalid;
        reject;
    }
}
```

Display status of the session to the RTR server.

```
louis@router> show validation session 192.168.1.100 detail
Session 192.168.1.100, State: up, Session index: 1
  Group: TEST-RPKI, Preference: 100
  Port: 8282
  Refresh time: 300s
  Hold time: 600s
  Record Life time: 3600s
  Serial (Full Update): 1
  Serial (Incremental Update): 1
    Session flaps: 2
    Session uptime: 00:25:07
    Last PDU received: 00:04:50
    IPv4 prefix count: 46478
    IPv6 prefix count: 8216
```

Show content of the database (list the PDUs)

```
louis@router> show validation database brief
RV database for instance master

Prefix                 Origin-AS Session                                 State   Mismatch
1.0.0.0/24-24              13335 192.168.1.100                           valid
1.1.1.0/24-24              13335 192.168.1.100                           valid
```

### Configure on Cisco

You may want to use the option to do SSH-based connection.

On Cisco, you can have only one RTR server per IP.

To configure a session for `192.168.1.100:8282`:
Replace `65001` by the configured ASN:

```
router bgp 65001
 rpki server 192.168.1.100
  transport tcp port 8282
 !
!
```

For an SSH session, you will also have to configure
`router bgp 65001 rpki server 192.168.1.100 password xxx`
where `xxx` is the password.
Some experimentations showed you have to configure
the username/password first, otherwise it will not accept the port.

```
router bgp 65001
 rpki server 192.168.1.100
  username rpki
  transport ssh port 8282
 !
!
ssh client tcp-window-scale 14
ssh timeout 120
```

The last two SSH statements solved an issue causing the
connection to break before receiving all the PDUs (TCP window full problem).

To visualize the state of the session:

```
RP/0/RP0/CPU0:ios#sh bgp rpki server 192.168.1.100

RPKI Cache-Server 192.168.1.100
  Transport: SSH port 8282
  Connect state: ESTAB
  Conn attempts: 1
  Total byte RX: 1726892
  Total byte TX: 452
  Last reset
    Timest: Apr 05 01:19:32 (04:26:58 ago)
    Reason: protocol error
SSH information
  Username: rpki
  Password: *****
  SSH PID: 18576
RPKI-RTR protocol information
  Serial number: 15
  Cache nonce: 0x0
  Protocol state: DATA_END
  Refresh  time: 600 seconds
  Response time: 30 seconds
  Purge time: 60 seconds
  Protocol exchange
    VRPs announced:  67358 IPv4   11754 IPv6
    VRPs withdrawn:     80 IPv4      34 IPv6
    Error Reports :      0 sent       0 rcvd
  Last protocol error
    Reason: response timeout
    Detail: response timeout while in DATA_START state
```

To visualize the accepted PDUs:

```
RP/0/RP0/CPU0:ios#sh bgp rpki table

  Network               Maxlen          Origin-AS         Server
  1.0.0.0/24            24              13335             192.168.1.100
  1.1.1.0/24            24              13335             192.168.1.100
```

### Configure on Arista
```
router bgp <asn>
   rpki cache <name>
      host <ipv4|ipv6|hostname> [vrf <vrfname>] [port <1-65535>] # default port is 323
      local-interface <interface>
      preference <1-10>                    # the lower the value, the more preferred
                                           # default is 5
      refresh-interval <1-86400 seconds>   # default is 3600
      expire-interval <600-172800 seconds> # default is 7200
      retry-interval <1-7200 seconds>      # default is 600
```
If multiple caches are configured, the preference controls the priority.  
Caches which are more preferred will be connected to first, if they are not reachable then connections will be attempted to less preferred caches.  
If caches have the same preference value, they will all be connected to and the VRPs that are synced from them will be merged together.

To visualize the state of the session:

```
show bgp rpki cache [<name>]
show bgp rpki cache counters [errors]
show bgp rpki roa summary
```

To visualize the accepted PDUs:

```
show bgp rpki roa (ipv4|ipv6) [prefix]
```

### Configure on Nokia SR OS

Configure a session to the RTR server (assuming it runs on `192.168.1.100:8282`):

```
[ex:/configure router "Base" origin-validation]
A:grhankin@br1-nyc# info
    rpki-session 192.168.1.100 {
        admin-state enable
        port 8282
    }
```

Add policies to validate or invalidate prefixes with an optional step of adding communities:

```
[ex:/configure policy-options]
A:grhankin@er2-nyc# info
    community "VRP_INVALID_COMM" {
        member "ext:4300:2" { }
    }
    community "VRP_NOT_FOUND_COMM" {
        member "ext:4300:1" { }
    }
    community "VRP_VALID_COMM" {
        member "ext:4300:0" { }
    }
    policy-statement "ORIGIN_POLICY" {
        entry 10 {
            from {
                origin-validation-state invalid
            }
            action {
                action-type reject
                community {
                    add ["VRP_INVALID_COMM"]
                }
            }
        }
        entry 20 {
            from {
                origin-validation-state not-found
            }
            action {
                action-type accept
                local-preference 100
                community {
                   add ["VRP_NOT_FOUND_COMM"]
                }
            }
        }
        entry 30 {
            from {
                origin-validation-state valid
            }
            action {
                action-type accept
                local-preference 110
                community {
                    add ["VRP_VALID_COMM"]
                }
            }
        }
    }
```
Display status of the session to the RTR server:

```
[/]
A:grhankin@br1-nyc# show router origin-validation rpki-session detail

===============================================================================
RPKI Session Information
===============================================================================
IP Address         : 192.168.1.100
-------------------------------------------------------------------------------
Port               : 8282               Oper State         : established
Uptime             : 0d 15:27:54        Flaps              : 38
Active IPv4 Records: 324319             Active IPv6 Records: 67880
Admin State        : Up                 Local Address      : n/a
Hold Time          : 600                Refresh Time       : 300
Stale Route Time   : 3600               Connect Retry      : 120
Serial ID          : 411                Session ID         : 15502
===============================================================================
No. of Sessions    : 1
===============================================================================
```

Show content of the database:

```
[/]
A:grhankin@br1-nyc# show router origin-validation database summary
===============================================================================
Static and Dynamic VRP Database Summary
===============================================================================
Source                                      IPv4 Entries      IPv6 Entries
Description
-------------------------------------------------------------------------------
192.168.1.100 [B]                           324319            67880
Static                                      0                 0
===============================================================================
```

```
[/]
A:grhankin@br1-nyc# show router origin-validation database origin-as 38016
===============================================================================
Static and Dynamic VRP Database Entries
===============================================================================
Prefix Range [Flags]                                            Origin AS
   Session IP [Flags]
-------------------------------------------------------------------------------
124.252.0.0/16-16 [Dynamic]                                     38016
    192.168.1.100 [B]
124.252.255.0/24-24 [Dynamic]                                   38016
    192.168.1.100 [B]
135.92.55.0/24-24 [Dynamic]                                     38016
    192.168.1.100 [B]
2406:c800::/32-32 [Dynamic]                                     38016
    192.168.1.100 [B]
2406:c800:a1ca::/48-48 [Dynamic]                                38016
    192.168.1.100 [B]
2406:c800:e000::/48-48 [Dynamic]                                38016
    192.168.1.100 [B]
-------------------------------------------------------------------------------
No. of VRP Database Entries: 6
-------------------------------------------------------------------------------
Flags: B = Base instance session
       M = Management instance session
       Static-V = Static-Valid; Static-I = Static-Invalid
===============================================================================
```

## License

Licensed under the BSD 3 License.
