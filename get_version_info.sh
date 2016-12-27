#!/bin/sh

ip=$1
usr_pass=$2


if [ ! -f "ssh2" ]
then
	echo "ssh2 not exist"
	exit
fi
#test to get correct username and password
result=`./ssh2 $ip "$usr_pass"`
num=`echo "${result}"|grep "^0"|wc -l`
if [ $num -eq 0 ]
then
	echo "${usr_pass} have not correct user and password"
	exit
#else
#	echo "get correct username and password"
fi

#line=`sed -n '/^0/p' tem.info`
username=`echo "${result}"|grep "^0"| awk '{print $2}'`
password=`echo "${result}"|grep "^0"| awk '{print $3}'`

#echo "username:"$username" password:"$password

file_name="os_info.sh"
if [ -f ${file_name} ]
then
	result=`./ssh2 $ip $username $password 2 "${file_name}"`
	echo "${result}"
else
	echo "file[$file_name] no exist"
	exit
fi

#sh get_version_info.sh 10.3.2.171 bomc1/asiainfo@bomc2/asiainfo
