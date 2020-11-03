#!/bin/sh
set -u

: ${TESTPROG:=./htpasswd}

verify()
{
	printf '  testing %s:\t' "$1"
	result="fail"
	if "$TESTPROG" -b -v "$2" "$3" "$4" >/dev/null; then
		result="pass"
	else
		status=1
	fi
	echo "[ $result ]"	
}

status=0

echo 'testing compatibility with upstream htpasswd:'
for i in plain sha bcrypt4 bcrypt10 md5 crypt3; do
	verify "$i" "test.htpasswd" "$i" "test"
done

echo 'testing basic operation'
"$TESTPROG" -c -b basictest test1 test1 || status=1
"$TESTPROG" -b -B basictest test2 test2 || status=1
"$TESTPROG" -b -s basictest test3 test3 || status=1
for i in $(seq 1 3); do
	verify "user test$i" basictest "test$i" "test$i"
done

exit "$status"