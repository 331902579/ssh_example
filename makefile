SYSTYPE:=$(shell uname)
CXX=g++

LDFLAG=-g -DHAVE_SYS_SOCKET_H -DHAVE_ARPA_INET_H -DHAVE_UNISTD_H

SSH2=/opt/wangcc/myDir/ssh/libssh2
LIB=-I$(SSH2)/include $(SSH2)/lib -lssh2 -ldl -lcrypto -lz

ssh2:ssh2.cpp
	$(CXX) -o ssh2 ssh2.cpp $(LDFLAG) $(LIB)
clean:
	rm -f ssh2
