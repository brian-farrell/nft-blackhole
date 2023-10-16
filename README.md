
# nft-blackhole
Daemon blocking IP addresses upon country or blacklist, using nftables

## Table of contents
- [Overview](#overview)
- [Installation](#installation)
  - [Manual](#manual)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Manual](#manual)
  - [With systemd](#with-systemd)
  - [Monitoring](#monitoring)
    - [List packets counters](#list-packets-counters)
    - [List table and sets for blackhole](#list-table-and-sets-for-blackhole)
  - [Refresh lists](#refresh-lists)
- [Credits](#credits)
- [License](#license)

## Overview

##### Features
- download publicly available blacklists and block IPs from them
- block or whitelist countries
- whitelist or blacklist from static entries, local files, or remote URLs (IPv4, IPv6, mixed)
- automatic retry on failed downloads (3 attempts with 5s delay)
- atomic operations - prevent loading incomplete rulesets on failures

##### Configuration file
###### In the configuration file you can define:
- IP versions supported (IPv4, IPv6)
- blocking policy (reject, drop)
- white list (static, file, or url sources)
- blacklist (static, file, or url sources)
- block output connections to blacklisted IPs
- nftables chain priority (e.g. -1, 0, or standard priority names)
- country IP list source (ipverse, ebrasha, ipdeny)
- list of countries
- policy for countries (accept, block)
- ports excluded from country blocks

## Installation
### Manual
##### Requirements
- nftables
- python 3.8+
- python3-jinja2
- python3-pyyaml
- python3-systemd
- systemd (for daemon)

##### File location
    /usr/local/bin/nft-blackhole.py
    /usr/local/share/nft-blackhole/nft-blackhole.j2
    /usr/local/etc/nft-blackhole.yaml
    /usr/local/lib/systemd/system/nft-blackhole.service
    /usr/local/lib/systemd/system/nft-blackhole-reload.service
    /usr/local/lib/systemd/system/nft-blackhole-reload.timer

## Configuration
#### Set the configuration in a file
`/usr/local/etc/nft-blackhole.yaml`

## Usage
### Manual
##### As root:
```shell
/usr/local/sbin/nft-blackhole.py start
/usr/local/sbin/nft-blackhole.py reload
/usr/local/sbin/nft-blackhole.py restart
/usr/local/sbin/nft-blackhole.py stop
```

### With systemd
##### As root:
```shell
systemctl enable nft-blackhole.service
systemctl start nft-blackhole.service
systemctl reload nft-blackhole.service
systemctl restart nft-blackhole.service
```

### Monitoring
#### List packets counters
```shell
nft list chain inet blackhole input
```

#### List table and sets for blackhole
```shell
nft list table inet blackhole
```

### Refresh lists
nft-blackhole can download new versions of any blacklist it uses. You can trigger this manually, however it is better to have it automatically and periodically done (either thanks to a cron job or to a Systemd timer).

#### Manual
```shell
/usr/local/sbin/nft-blackhole.py reload
systemctl reload nft-blackhole.service
```

#### Crontab
```
0 */6 * * * systemctl reload nft-blackhole.service
```

#### Systemd Timer
```bash
systemctl enable --now nft-blackhole-reload.timer
systemctl list-timers --all
```

## Credits
[ipverse/geo-ip-blocks](https://github.com/ipverse/geo-ip-blocks) - Daily-updated IPv4 and IPv6 prefixes by country, derived from network registration data.

[ebrasha/cidr-ip-ranges-by-country](https://github.com/ebrasha/cidr-ip-ranges-by-country) - Hourly-updated IPv4 and IPv6 CIDR ranges by country, designed for geolocation, firewall rules, and cybersecurity filtering.

[IPdeny](https://www.ipdeny.com/ipblocks/) - A free public service providing downloadable country-specific IP address zone files in CIDR format.

[FireHOL IP Lists](https://iplists.firehol.org/) - A public repository that aggregates, analyzes, and compares security blocklists and cybercrime IP feeds.

## License
Code released under [MIT](./LICENSE) license.
