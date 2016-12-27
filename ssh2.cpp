//============================================================================
// Name        : ssh2.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <libssh2.h>

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
# ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#include <iostream>
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <iostream>
#include <string.h>
#include <vector>

using namespace std;
vector<string> Split(const char* data,const char c)
{
	vector<string> vec;
	size_t cur = 0;
	string strData(data);
	int len = strlen(data) + 1;
	while((int)cur < len)
	{
		string::size_type pos = strData.find(c,cur);
		if (pos == string::npos)
		{
			break;
		}

		string s = strData.substr(cur,pos - cur);
		vec.push_back(s);
		cur = pos + 1;
	}

	string s = strData.substr(cur,len - cur);
	vec.push_back(s);

	return vec;
}
int readfile(const char* filename ,char** ppBuf)
{
	FILE* fp;
	fp = fopen(filename,"rb");
	if(fp == NULL)
	{
		fprintf(stdout,"open file %s error!\n", filename);
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	int len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	*ppBuf = new char[len];
	memset(*ppBuf, 0, len);
	fread(*ppBuf, 1, len, fp);
	fclose(fp);
	return len;
}

int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    FD_ZERO(&fd);

    FD_SET(socket_fd, &fd);

    /* now make sure we wait in the correct direction */
    dir = libssh2_session_block_directions(session);

    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;

    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;

    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);

    return rc;
}

int test(const char *hostname,const char *username,const char *password)
{
	unsigned long hostaddr;
	int sock;
	struct sockaddr_in sin;
	const char *fingerprint;
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;
	int rc;
	int exitcode;
	char *exitsignal=(char *)"none";
	int bytecount = 0;
	size_t len;
	LIBSSH2_KNOWNHOSTS *nh;
	int type;
	char * command = NULL;
#ifdef WIN32
	WSADATA wsadata;
	WSAStartup(MAKEWORD(2,0), &wsadata);
#endif

	rc = libssh2_init (0);
	if (rc != 0) {
		fprintf (stdout, "libssh2 initialization failed (%d)\n", rc);
		return 1;
	}

	hostaddr = inet_addr(hostname);

	/* Ultra basic "connect to port 22 on localhost"
	 * Your code is responsible for creating the socket establishing the
	 * connection
	 */
	sock = socket(AF_INET, SOCK_STREAM, 0);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(22);
	sin.sin_addr.s_addr = hostaddr;
	if (connect(sock, (struct sockaddr*)(&sin),
			sizeof(struct sockaddr_in)) != 0) {
		fprintf(stdout, "failed to connect!\n");
		return -1;
	}

	/* Create a session instance */
	session = libssh2_session_init();
	if (!session)
		return -1;

	/* tell libssh2 we want it all done non-blocking */
	libssh2_session_set_blocking(session, 0);

	/* ... start it up. This will trade welcome banners, exchange keys,
	 * and setup crypto, compression, and MAC layers
	 */
	while ((rc = libssh2_session_startup(session, sock)) ==
			LIBSSH2_ERROR_EAGAIN);
	if (rc) {
		fprintf(stdout, "Failure establishing SSH session: %d\n", rc);
		return -1;
	}

	nh = libssh2_knownhost_init(session);
	if(!nh) {
		/* eeek, do cleanup here */
		return 2;
	}

	/* read all hosts from here */
	libssh2_knownhost_readfile(nh, "known_hosts",
			LIBSSH2_KNOWNHOST_FILE_OPENSSH);

	/* store all known hosts to here */
	libssh2_knownhost_writefile(nh, "dumpfile",
			LIBSSH2_KNOWNHOST_FILE_OPENSSH);

	fingerprint = libssh2_session_hostkey(session, &len, &type);
	if(fingerprint) {
		struct libssh2_knownhost *host;
#if LIBSSH2_VERSION_NUM >= 0x010206
		/* introduced in 1.2.6 */
		int check = libssh2_knownhost_checkp(nh, hostname, 22,
				fingerprint, len,
				LIBSSH2_KNOWNHOST_TYPE_PLAIN|
				LIBSSH2_KNOWNHOST_KEYENC_RAW,
				&host);
#else
	/* 1.2.5 or older */
	int check = libssh2_knownhost_check(nh, hostname,
			fingerprint, len,
			LIBSSH2_KNOWNHOST_TYPE_PLAIN|
			LIBSSH2_KNOWNHOST_KEYENC_RAW,
			&host);
#endif
/*fprintf(stdout, "Host check: %d, key: %s\n", check,
		(check <= LIBSSH2_KNOWNHOST_CHECK_MISMATCH)?
				host->key:"<none>"); */

/*****
 * At this point, we could verify that 'check' tells us the key is
 * fine or bail out.
 *****/
	}
	else {
		/* eeek, do cleanup here */
		return 3;
	}
	libssh2_knownhost_free(nh);

	if ( strlen(password) != 0 ) {
		/* We could authenticate via password */
		while ((rc = libssh2_userauth_password(session, username, password)) ==
				LIBSSH2_ERROR_EAGAIN);
		if (rc) {
					fprintf(stdout, "1 %s %s Authentication by password failed(%d).\n",username,password,rc);
				}
		else
		{
			fprintf(stdout, "0 %s %s",username,password);
		}
	}
	else {
		/* Or by public key */
		while ((rc = libssh2_userauth_publickey_fromfile(session, username,
				"/home/user/"
				".ssh/id_rsa.pub",
				"/home/user/"
				".ssh/id_rsa",
				password)) ==
						LIBSSH2_ERROR_EAGAIN);
		if (rc) {
			fprintf(stdout, "1 %s %s Authentication by public key failed(%d)\n",username,password,rc);
		}
		else
		{
			fprintf(stdout, "0 %s %s",username,password);
		}
	}

shutdown:

	libssh2_session_disconnect(session,
			"Normal Shutdown, Thank you for playing");
	libssh2_session_free(session);

#ifdef WIN32
	closesocket(sock);
#else
	close(sock);
#endif
	//fprintf(stdout, "all done\n");

	libssh2_exit();

	return rc;
}

int testecho(const char* hostname, const char* usr_pass,char aFlag, char bFlag)
{
	vector<string> data = Split(usr_pass,bFlag);
	int size = data.size();
	if( size > 0)
	{
		for(int i = 0; i < size ; i ++)
		{
			string tmpstr = data[i];

			vector<string> info = Split(tmpstr.c_str(),aFlag);

			if(info.size() == 2)
			{
				string username = info[0];
				string password = info[1];
				if( 0 == test(hostname,username.c_str(),password.c_str()))
				{
					return 0;
				}
			}
		}
	}

	return 0;
}

int execute(const char *hostname,const char *username,const char *password,const char *typeparam,int _type)
{
	unsigned long hostaddr;
	int sock;
	struct sockaddr_in sin;
	const char *fingerprint;
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;
	int rc;
	int exitcode;
	char *exitsignal=(char *)"none";
	int bytecount = 0;
	size_t len;
	LIBSSH2_KNOWNHOSTS *nh;
	int type;
	char * command = NULL;
#ifdef WIN32
	WSADATA wsadata;
	WSAStartup(MAKEWORD(2,0), &wsadata);
#endif

	rc = libssh2_init (0);
	if (rc != 0) {
		fprintf (stdout, "libssh2 initialization failed (%d)\n", rc);
		return 1;
	}

	hostaddr = inet_addr(hostname);

	/* Ultra basic "connect to port 22 on localhost"
	 * Your code is responsible for creating the socket establishing the
	 * connection
	 */
	sock = socket(AF_INET, SOCK_STREAM, 0);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(22);
	sin.sin_addr.s_addr = hostaddr;
	if (connect(sock, (struct sockaddr*)(&sin),
			sizeof(struct sockaddr_in)) != 0) {
		fprintf(stdout, "failed to connect!\n");
		return -1;
	}

	/* Create a session instance */
	session = libssh2_session_init();
	if (!session)
		return -1;

	/* tell libssh2 we want it all done non-blocking */
	libssh2_session_set_blocking(session, 0);

	/* ... start it up. This will trade welcome banners, exchange keys,
	 * and setup crypto, compression, and MAC layers
	 */
	while ((rc = libssh2_session_startup(session, sock)) ==
			LIBSSH2_ERROR_EAGAIN);
	if (rc) {
		fprintf(stdout, "Failure establishing SSH session: %d\n", rc);
		return -1;
	}

	nh = libssh2_knownhost_init(session);
	if(!nh) {
		/* eeek, do cleanup here */
		return 2;
	}

	/* read all hosts from here */
	libssh2_knownhost_readfile(nh, "known_hosts",
			LIBSSH2_KNOWNHOST_FILE_OPENSSH);

	/* store all known hosts to here */
	libssh2_knownhost_writefile(nh, "dumpfile",
			LIBSSH2_KNOWNHOST_FILE_OPENSSH);

	fingerprint = libssh2_session_hostkey(session, &len, &type);
	if(fingerprint) {
		struct libssh2_knownhost *host;
#if LIBSSH2_VERSION_NUM >= 0x010206
		/* introduced in 1.2.6 */
		int check = libssh2_knownhost_checkp(nh, hostname, 22,
				fingerprint, len,
				LIBSSH2_KNOWNHOST_TYPE_PLAIN|
				LIBSSH2_KNOWNHOST_KEYENC_RAW,
				&host);
#else
	/* 1.2.5 or older */
	int check = libssh2_knownhost_check(nh, hostname,
			fingerprint, len,
			LIBSSH2_KNOWNHOST_TYPE_PLAIN|
			LIBSSH2_KNOWNHOST_KEYENC_RAW,
			&host);
#endif
/*fprintf(stdout, "Host check: %d, key: %s\n", check,
		(check <= LIBSSH2_KNOWNHOST_CHECK_MISMATCH)?
				host->key:"<none>"); */

/*****
 * At this point, we could verify that 'check' tells us the key is
 * fine or bail out.
 *****/
	}
	else {
		/* eeek, do cleanup here */
		return 3;
	}
	libssh2_knownhost_free(nh);

	if ( strlen(password) != 0 ) {
		/* We could authenticate via password */
		while ((rc = libssh2_userauth_password(session, username, password)) ==
				LIBSSH2_ERROR_EAGAIN);
		if (rc) {
					fprintf(stdout, "Authentication by password failed(%d).\n",rc);
					goto shutdown;
				}
	}
	else {
		/* Or by public key */
		while ((rc = libssh2_userauth_publickey_fromfile(session, username,
				"/home/user/"
				".ssh/id_rsa.pub",
				"/home/user/"
				".ssh/id_rsa",
				password)) ==
						LIBSSH2_ERROR_EAGAIN);
		if (rc) {
			fprintf(stdout, "Authentication by public key failed(rc)\n",rc);
			goto shutdown;
		}
	}

#if 0
	libssh2_trace(session, ~0 );
#endif

	/* Exec non-blocking on the remove host */
	while( (channel = libssh2_channel_open_session(session)) == NULL &&
			libssh2_session_last_error(session,NULL,NULL,0) ==
					LIBSSH2_ERROR_EAGAIN )
	{
		waitsocket(sock, session);
	}
	if( channel == NULL )
	{
		fprintf(stdout,"channel Error\n");
		goto shutdown;
	}

	if( 2 == _type)
	{
		int nLen = readfile(typeparam,&command);
		if(nLen == -1)
		{
			fprintf(stdout,"read file error!\n");
			goto shutdown;
		}
	}
	else
	{
		int len = strlen(typeparam) + 1;
		command = new char[len];
		strncpy(command,typeparam,len);
	}

	while( (rc = libssh2_channel_exec(channel, command)) ==
			LIBSSH2_ERROR_EAGAIN )
	{
		waitsocket(sock, session);
	}
	if( rc != 0 )
	{
		fprintf(stdout,"Error\n");
		goto shutdown;
	}
	for( ;; )
	{
		/* loop until we block */
		int rc;
		do
		{
			char buffer[0x4000];
			rc = libssh2_channel_read( channel, buffer, sizeof(buffer) );
			if( rc > 0 )
			{
				int i;
				bytecount += rc;
				//fprintf(stdout, "We read:\n");
				for( i=0; i < rc; ++i )
					fputc( buffer[i], stdout);
				//fprintf(stdout, "\n");
			}
			else {
				//fprintf(stdout, "libssh2_channel_read returned %d\n", rc);
			}
		}
		while( rc > 0 );

		/* this is due to blocking that would occur otherwise so we loop on
	           this condition */
		if( rc == LIBSSH2_ERROR_EAGAIN )
		{
			waitsocket(sock, session);
		}
		else
			break;
	}
	exitcode = 127;
	while( (rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN )
		waitsocket(sock, session);

	if( rc == 0 )
	{
		exitcode = libssh2_channel_get_exit_status( channel );
		libssh2_channel_get_exit_signal(channel, &exitsignal,
				NULL, NULL, NULL, NULL, NULL);
	}

/*	if (exitsignal)
		printf("\nGot signal: %s\n", exitsignal);
	else
		printf("\nEXIT: %d bytecount: %d\n", exitcode, bytecount);
*/
	libssh2_channel_free(channel);
	channel = NULL;

shutdown:

	if (NULL != command) delete[] command;

	libssh2_session_disconnect(session,
			"Normal Shutdown, Thank you for playing");
	libssh2_session_free(session);

#ifdef WIN32
	closesocket(sock);
#else
	close(sock);
#endif
	//fprintf(stdout, "all done\n");

	libssh2_exit();

	return 0;
}

int transfer(const char *hostname,const char *username,const char *password,const char *loclfile,const char *scppath)
{
	unsigned long hostaddr;
	int sock, i, auth_pw = 1;
	struct sockaddr_in sin;
	const char *fingerprint;
	LIBSSH2_SESSION *session = NULL;
	LIBSSH2_CHANNEL *channel;
	FILE *local;
	int rc;
	char mem[1024];
	size_t nread;
	char *ptr;
	struct stat fileinfo;

#ifdef WIN32
	WSADATA wsadata;

	WSAStartup(MAKEWORD(2,0), &wsadata);
#endif

	if ( NULL != hostname) {
		hostaddr = inet_addr(hostname);
	} else {
		hostaddr = htonl(0x7F000001);
	}

	rc = libssh2_init (0);
	if (rc != 0) {
		fprintf (stdout, "libssh2 initialization failed (%d)\n", rc);
		return 1;
	}

	local = fopen(loclfile, "rb");
	if (!local) {
		fprintf(stdout, "Can't open local file %s\n", loclfile);
		return -1;
	}

	stat(loclfile, &fileinfo);

	/* Ultra basic "connect to port 22 on localhost"
	 * Your code is responsible for creating the socket establishing the
	 * connection
	 */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(-1 == sock) {
		fprintf(stdout, "failed to create socket!\n");
		return -1;
	}

	sin.sin_family = AF_INET;
	sin.sin_port = htons(22);
	sin.sin_addr.s_addr = hostaddr;
	if (connect(sock, (struct sockaddr*)(&sin),
			sizeof(struct sockaddr_in)) != 0) {
		fprintf(stdout, "failed to connect!\n");
		return -1;
	}

	/* Create a session instance
	 */
	session = libssh2_session_init();
	if(!session)
		return -1;

	/* ... start it up. This will trade welcome banners, exchange keys,
	 * and setup crypto, compression, and MAC layers
	 */
	rc = libssh2_session_startup(session, sock);
	if(rc) {
		fprintf(stdout, "Failure establishing SSH session: %d\n", rc);
		return -1;
	}

	/* At this point we havn't yet authenticated.  The first thing to do
	 * is check the hostkey's fingerprint against our known hosts Your app
	 * may have it hard coded, may go to a file, may present it to the
	 * user, that's your call
	 */
	fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
/*	fprintf(stdout, "Fingerprint: ");
	for(i = 0; i < 20; i++) {
		fprintf(stdout, "%02X ", (unsigned char)fingerprint[i]);
	}
	fprintf(stdout, "\n");
*/
	if (auth_pw) {
		/* We could authenticate via password */
		if (libssh2_userauth_password(session, username, password)) {
			fprintf(stdout, "Authentication by password failed.\n");
			goto shutdown;
		}
	} else {
		/* Or by public key */
		if (libssh2_userauth_publickey_fromfile(session, username,
				"/home/username/.ssh/id_rsa.pub",
				"/home/username/.ssh/id_rsa",
				password)) {
			fprintf(stdout, "\tAuthentication by public key failed\n");
			goto shutdown;
		}
	}

	/* Send a file via scp. The mode parameter must only have permissions! */
	channel = libssh2_scp_send(session, scppath, fileinfo.st_mode & 0777,
			(unsigned long)fileinfo.st_size);

	if (!channel) {
		char *errmsg;
		int errlen;
		int err = libssh2_session_last_error(session, &errmsg, &errlen, 0);
		fprintf(stdout, "Unable to open a session: (%d) %s\n", err, errmsg);
		goto shutdown;
	}

	//fprintf(stdout, "SCP session waiting to send file\n");
	do {
		nread = fread(mem, 1, sizeof(mem), local);
		if (nread <= 0) {
			/* end of file */
			fprintf(stdout, "0 send success\n");
			break;
		}
		ptr = mem;

		do {
			/* write the same data over and over, until error or completion */
			rc = libssh2_channel_write(channel, ptr, nread);
			if (rc < 0) {
				fprintf(stdout, "ERROR %d\n", rc);
				break;
			}
			else {
				/* rc indicates how many bytes were written this time */
				ptr += rc;
				nread -= rc;
			}
		} while (nread);

	} while (1);

	//fprintf(stdout, "Sending EOF\n");
	libssh2_channel_send_eof(channel);

	//fprintf(stdout, "Waiting for EOF\n");
	libssh2_channel_wait_eof(channel);

	//fprintf(stdout, "Waiting for channel to close\n");
	libssh2_channel_wait_closed(channel);

	libssh2_channel_free(channel);
	channel = NULL;

shutdown:

	if(session) {
		libssh2_session_disconnect(session, "Normal Shutdown, Thank you for playing");
		libssh2_session_free(session);
	}
#ifdef WIN32
	closesocket(sock);
#else
	close(sock);
#endif
	if (local)
		fclose(local);
	//fprintf(stdout, "all done\n");

	libssh2_exit();

	return 0;
}

void Help(FILE* file, const char* program_name)
{
	fprintf(file,
		"--------------------------------\n"
		"Program information options:\n"
		" %s       print help info\n"
		"--------------------------------\n"
		"Example:\n"
		" %s ip username password type param\n"
		" --test connect: %s 10.3.2.171 \"bomc/asiainfo|bomc1/asiainfo2\" \"/|\" \n"
		" --test connect: %s 10.3.2.171 bomc asiainfo 0 \n"
		" --execute cmd: %s 10.3.2.171 bomc asiainfo 1 \"cmd\"\n"
		" --execut file content: %s 10.3.2.171 bomc asiainfo 2 shell_file_path_name\n"
		" --transfer file: %s 10.3.2.171 bomc asiainfo 3 source_path_file dest_path_file\n"
		"\n"
		, program_name
		, program_name
		, program_name
		, program_name
		, program_name
		, program_name
		);
}

int main(int argc, char *argv[])
{
	if(argc < 3)
	{
		Help(stdout, argv[0]);
		return 0;
	}
	const char* programName = argv[0];
	const char *hostname = "127.0.0.1";
	const char *username    = "user";
	const char *password    = "password";
	int type = 0;
	const char *typeparam1 = "source_filename";
	const char *typeparam2 = "desc_temp_file";
	if (argc > 1)
	{
		/* must be ip address only */
		hostname = argv[1];
	}
	if (argc > 2) {
		username = argv[2];
	}
	if( 3 == argc)
	{
		return testecho(hostname,username,'/','|');
	}

	if (argc > 3) {
		password = argv[3];
	}

	if( 4 == argc)
	{
		if(2 == strlen(password))
		{
			return testecho(hostname,username,password[0],password[1]);
		}
	}

	if (argc > 4) {
		type = atoi(argv[4]);
	}

	if (argc > 5) {
		typeparam1 = argv[5];
	}

	switch(type)
	{
	case 0:
		test(hostname,username,password);
		break;
	case 1:
	case 2:
		execute(hostname,username,password,typeparam1,type);
		break;
	case 3:
		if (argc > 6) {
			typeparam2 = argv[6];
		}
		transfer(hostname,username,password,typeparam1,typeparam2);
		break;

	default:
		Help(stdout, argv[0]);
		break;
	}

	return 0;
}
