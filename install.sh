#!/bin/sh

ip=$1
usr_pass=$2
install_file_name=$3
install_path=$4
if [ -z "$install_path" ]
then
	install_path=$HOME
fi
UUID=$5
HostId=$6
HubIpPort=$7

if [ ! -f "ssh2" ]
then
	echo "ssh2 not exist"
	exit
fi

#test to get correct username and password
result=`./ssh2 $ip "$usr_pass"`
num=`echo "${result}" |grep "^0" |wc -l`
if [ ${num} -eq 0 ]
then
	echo "${result}"
	echo "${usr_pass} have not correct user and password"
	exit
else
	echo "get correct username and password"
fi

#line=`sed -n '/^0/p' tem.info`
username=`echo "${result}"|grep "^0"| awk '{print $2}'`
password=`echo "${result}"|grep "^0"| awk '{print $3}'`

echo "username:"${username}" password:"${password}

#send package
#package is exist
if [ -f ../resource/${install_file_name} ]
then
	result=`./ssh2 ${ip} ${username} ${password} 3 ../resource/${install_file_name} ./${install_file_name}`
	num=`echo "${result}" |grep "^0" |wc -l`
	if [ ${num} -eq 1 ]
	then
		echo "send ${install_file_name} success"
	else
		echo "${result}"
		echo "send ${install_file_name} failed"
		exit
	fi
else
	echo "file[$install_file_name] no exist"
	exit
fi

#file_name=`echo ${install_file_name} | awk -F "." '{print $1}'`
file_name=`echo ${install_file_name} | sed s/.tar.gz//g`

#install
os_type=`./ssh2 ${ip} ${username} ${password} 1 "uname"`
if [ "${os_type}" = "HP-UX" ]
then
	result=`./ssh2 ${ip} ${username} ${password} 1 "/usr/contrib/bin/gzip -df ${file_name}.tar.gz 2>&1;tar -xf ${file_name}.tar 2>&1;cd ${file_name} 2>&1;\
	sh agent60_update.sh \"${install_path}\" \"${UUID}\" \"${HostId}\" \"${HubIpPort}\""`
else
	result=`./ssh2 ${ip} ${username} ${password} 1 "gzip -df ${file_name}.tar.gz 2>&1;tar -xf ${file_name}.tar 2>&1;cd ${file_name} 2>&1;\
	sh agent60_update.sh \"${install_path}\" \"${UUID}\" \"${HostId}\" \"${HubIpPort}\""`
fi
	
num=`echo "${result}" |wc -l`
if [ ${num} -eq 0 ]
then
	echo "install failed"
else
	echo "tar cd and sh agent60_update.sh"
	echo "${result}"
fi

#sh install.sh 10.3.2.171 bomc1/asiainfo@bomc/asiainfo agent60_Linux_sles_32.tar.gz /data3/bomc/wangcc5/tmp uuid1234 hostid4567 10.3.2.171:4567 