#!/bin/sh

#output example
#	==================================================================
#	AIX53@10.3.2.53		AIX PSO-BOMC 3 5 000CA7AF4C00
#	"os_type":"aix", "os_version":"5.3", "os_bit":"32"
#	==================================================================
#	AIX61@10.10.10.201	AIX ibm201 1 6 00C51B744C00
#	"os_type":"aix", "os_version":"6.1", "os_bit":"32"
#	==================================================================
#	HP-UX@10.10.10.172	HP-UX hp172 B.11.11 U 9000/800 861214278 unlimited-user license
#	"os_type":"hp", "os_version":"11.11", "os_bit":"32"
#	==================================================================
#	SunOS@10.3.3.68		SunOS ngboss-gz-ip68 5.10 Generic_137111-08 sun4u sparc SUNW,Sun-Fire-V890
#	"os_type":"sun", "os_version":"5.10", "os_bit":"32"
#	==================================================================
#	SUSE@10.3.2.171		Linux SLES-103 2.6.16.60-0.54.5-smp #1 SMP Fri Sep 4 01:28:03 UTC 2009 i686 i686 i386 GNU/Linux
#						SUSE Linux Enterprise Server 10 (i586)
#						VERSION = 10
#						PATCHLEVEL = 3
#	"os_type":"suse", "os_version":"10", "os_bit":"32"
#	==================================================================
#	Red Hat:			Linux keyon 2.6.18-53.el5 #1 SMP Wed Oct 10 16:34:02 EDT 2007 i686 i686 i386 GNU/Linux
#						Red Hat Enterprise Linux Server release 5.1 (Tikanga)
#	"os_type":"redhat", "os_version":"5.1", "os_bit":"32"
#	==================================================================
#	Fedaro 23:			Linux localhost.localdomain 4.4.9-300.fc23.x86_64 #1 SMP Wed May 4 23:56:27 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
#						Fedora release 23 (Twenty Three)
#	"os_type":"fedora", "os_version":"23", "os_bit":"64"
#	==================================================================
#	CentOS:				Linux vm 2.6.32-358.el6.x86_64 #1 SMP Fri Feb 22 00:31:26 UTC 2013 x86_64 x86_64 x86_64 GNU/Linux
#						#CentOS release 6.4 (Final)
#						redhat 4
#	"os_type":"redhat", "os_version":"4", "os_bit":"64"
#	==================================================================

os_type=`uname`
os_version=""
os_bit=`getconf LONG_BIT`

pro_name="agent60"

if [ $os_type = "Linux" ]
then
	os_type="linux"
	os_info=`cat /proc/version`
	if [ 0 -lt `echo $os_info |grep 'SUSE Linux' | wc -c` ]		####if [[ "$os_info" =~ "SUSE Linux" ]]##
	then
		os_type="suse"
		#/etc/SuSE-release
		if [ -f "/etc/SuSE-release" ]
		then
			os_version=`cat /etc/SuSE-release| awk -F '=' '{gsub(/ /,"",$1); if($1=="VERSION"){gsub(/ /,"",$2);print $2;}}'`
		else
			os_version=`lsb_release -a |awk -F':' '{if($1 == "Release") {print $2;}}' | sed 's/\t//g'`
		fi
	elif [ 0 -lt `echo $os_info |grep 'Red Hat' | wc -c` ]		#include Red Hat(5 show el5)  Fedora(23 show fc23) Centos(6 show el6)
	then
		if [ -f "/etc/redhat-release" ]
		then
			release=`cat /etc/redhat-release| sed 's/^\#.*//g' | sed /^$/d | head -1`		#ignore the line which start with '#'
			if [ 0 -eq `echo $release | wc -c` ]
			then
				release=`cat /etc/redhat-release`
			fi
			
			if [ 0 -lt `echo $release |grep 'Red Hat' | wc -c` ]
			then
				os_type="redhat"
			elif [ 0 -lt `echo $release |grep 'Fedora' | wc -c` ]
			then
				os_type="fedora"
			elif [ 0 -lt `echo $release |grep 'CentOS' | wc -c` ]
			then
				os_type="centos"
			else
				#os_type=`echo $release | awk -F 'release' '{ if(NR==1) {gsub(/^[[:blank:]]*/,"",$1);gsub(/[[:blank:]]*$/,"",$1); print $1;} }'`
				#os_version=`echo $release | awk -F 'release' '{ gsub(/ /,"",$2);gsub(/\(.*\)/,"",$2); print $2 }'`	
				os_type=`echo $release | sed 's/[.0-9]//g' | sed 's/(.*)//g'| sed 's/^[[:blank:]]*//g' |sed 's/[[:blank:]]*$//g'| tr '[A-Z]' '[a-z]'`
			fi
			#os_version=`echo $release | awk -F 'release' '{ gsub(/ /,"",$2);gsub(/\(.*\)/,"",$2); print $2 }'`	
			os_version=`echo $release | sed 's/[^.0-9]//g'| sed 's/ //g'`
		else
			os_type="linux"
			os_version=`uname -r`
		fi
	else
		os_type="linux"
		os_version=`uname -r`
	fi
	
	# check weather get correct os bit
	if [ -z $os_bit ]
	then
		if [ 0 -lt `uname -a|grep 'x86_64' |wc -c` ]
		then
			os_bit=64
		else
			os_bit=32
		fi
	fi
elif [ $os_type = "AIX" ]
then
	os_type="aix"
	release_number=`uname -r`
	system_version=`uname -v`
	os_version=${system_version}"."${release_number}
	#get os bit
	if [ 0 -lt `prtconf |grep 'Kernel Type' |grep '64' | wc -c` ]
	then
		os_bit=64
	else
		os_bit=32
	fi
elif [ $os_type = "HP-UX" ]
then
	os_type="hp"
	release_number=`uname -r`
	system_version=`uname -v`
#	os_version=${system_version}"."${release_number}
	os_version=`echo $release_number | sed 's/[^.0-9]//g' | sed 's/^\.//g' `
	os_bit=`getconf KERNEL_BITS`
elif [ $os_type = "SunOS" ]
then
	os_type="sun"
	os_version=`uname -r`
	os_bit=`isainfo -b`
else
	os_type=`echo $os_type |sed 's/-//g'|sed 's/ //g' | tr '[A-Z]' '[a-z]' `
	os_version=`uname -r | sed 's/[^.0-9]//g'| sed 's/^\.//g' | sed 's/ //g' `
fi

# check weather get correct os bit
if [ -z $os_bit ]
then
	os_bit=32
fi

# fix os version, only take two field.
os_version=`echo $os_version | cut -d '.' -f 1,2`
echo "{\"osType\":\"$os_type\",\"osBit\":\"$os_bit\",\"osVersion\":\"$os_version\"}"
