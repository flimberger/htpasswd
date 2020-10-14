#!/bin/sh
set -u
status=0
for i in plain sha bcrypt4 bcrypt10 md5 crypt3; do
	echo "testing $i:"
	./htpasswd -b -v "test.htpasswd" "$i" "test" || status=1
done
exit "$status"
