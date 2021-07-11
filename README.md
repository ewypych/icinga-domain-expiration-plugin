ICINGA2 Check Domain Expiration plugin
======================================

This plugin has been created especially for Icinga2, but it is compatible with Nagios 4 too. Plugin checks expiration date of domain and informs how many days are left until domain expires. In the "command" directory you find examples of command definitions for both Nagios and Icinga2.

Example of use
--------------

```sh
./check_domain_expiration.sh -d google.com -w 60 -c 30
or
./check_domain_expiration.sh -d youdomain.com.au -s crazydomains.com
```

Requirements
------------

Plugin requires the following packages installed on your Icinga/Nagios node:

* WHOIS
* AWK

Supported Top-level Domains
----------------------------

* com
* pl
* org
* info
* net
* center
* pro
* me
* su
* nu
* ru
* xn--p1ai (рф)
* moscow
* se
* asia
* art
* cz
* fr
* re
* yt
* tf
* pm
* shop
* tv
* ua
* im
* uk
* co.uk
* tech
* co
* digital
* br
* it
* club
* ie
* id
* dev
* io
* rocks
* space
* us
* in

Supported Whois Servers

* whois.crazydomains.com
* whois.cloudflare.com
* whois.drs.ua, whois.pp.ua, whois.biz.ua

License
-------

[MIT](https://tldrlegal.com/license/mit-license)

Author
------

[Emil Wypych](https://emilwypych.com) [@gmail](mailto:wypychemil@gmail.com)
[Github Repo](https://github.com/ewypych/icinga-domain-expiration-plugin)
