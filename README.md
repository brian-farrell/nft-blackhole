
# nft-blackhole
##### _*Block IP addresses by country or blacklist, using nftables*_
<br/>

> [!CAUTION]
> __This repo is undergoing a MAJOR refactoring at the moment!!!__
> <br/>Please __*DO NOT*__ attempt to use this code in its current state (including the `main` branch)!!!
> <br/>
> <br/>A new release is planed for mid-November, 2026, with new improvements, including
> <br/>the ability to install from PyPi, as well as from an RPM
> <br/>
> <br/>If you can't wait, I highly recommend using the code in the upstream repo, available
> <br/>at [https://github.com/tomasz-c/nft-blackhole](https://github.com/tomasz-c/nft-blackhole)


## Table of contents

- [Overview](#overview)
- [Monitoring](#monitoring)
  - [List packets counters](#list-packets-counters)
  - [List table and sets for blackhole](#list-table-and-sets-for-blackhole)
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

### Monitoring
#### List packets counters
```shell
nft list chain inet blackhole input
```

#### List table and sets for blackhole
```shell
nft list table inet blackhole
```

## Credits
[country-ip-blocks](https://github.com/herrbischoff/country-ip-blocks) - CIDR country-level IP lists,

[ipverse/geo-ip-blocks](https://github.com/ipverse/geo-ip-blocks) - Daily-updated IPv4 and IPv6 prefixes by country, derived from network registration data.

[https://iplists.firehol.org/](https://iplists.firehol.org/) - aggregated, publicly available blacklists

[ebrasha/cidr-ip-ranges-by-country](https://github.com/ebrasha/cidr-ip-ranges-by-country) - Hourly-updated IPv4 and IPv6 CIDR ranges by country, designed for geolocation, firewall rules, and cybersecurity filtering.

[IPdeny](https://www.ipdeny.com/ipblocks/) - A free public service providing downloadable country-specific IP address zone files in CIDR format.

[FireHOL IP Lists](https://iplists.firehol.org/) - A public repository that aggregates, analyzes, and compares security blocklists and cybercrime IP feeds.

## License
Code released under [MIT](./LICENSE) license.
