/*  see copyright notice in squirrel.h */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#if defined(_MSC_VER) && defined(_DEBUG)
#include <crtdbg.h>
#include <conio.h>
#endif
#include <squirrel.h>
#include <sqstdblob.h>
#include <sqstdsystem.h>
#include <sqstdio.h>
#include <sqstdmath.h>
#include <sqstdstring.h>
#include <sqstdaux.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#ifdef SQUNICODE
#define scfprintf fwprintf
#define scvprintf vfwprintf
#else
#define scfprintf fprintf
#define scvprintf vfprintf
#endif


void PrintVersionInfos();

SQInteger quit(HSQUIRRELVM v)
{
	int* done;
	sq_getuserpointer(v, -1, (SQUserPointer*)&done);
	*done = 1;
	return 0;
}

void printfunc(HSQUIRRELVM SQ_UNUSED_ARG(v), const SQChar* s, ...)
{
	va_list vl;
	va_start(vl, s);
	scvprintf(stdout, s, vl);
	va_end(vl);
}

void errorfunc(HSQUIRRELVM SQ_UNUSED_ARG(v), const SQChar* s, ...)
{
	va_list vl;
	va_start(vl, s);
	scvprintf(stderr, s, vl);
	va_end(vl);
}


int stripos ( char* haystack, char* needle, int haystackLength, int needleLength ){
	for (int i = 0; i < haystackLength - needleLength; i++)
	{
		if (memcmp(haystack+i, needle, needleLength) == 0)
		{
			return 1;
		}
	}

	return -1;
}

#define _INTERACTIVE 0
#define _DONE 2
#define _ERROR 3

int executeVm(HSQUIRRELVM v, SQInteger* retval, char* filename)
{
	*retval = 0;

	HSQOBJECT obj;

	if (SQ_SUCCEEDED(sqstd_loadfile(v, filename, SQTrue))) {
		int callargs = 1;

		sq_getstackobj(v, -1, &obj);
		sq_addref(v, &obj);
		sq_pop(v, 1);

		SQRESULT result;
		sq_pushobject(v, obj);
		sq_pushroottable(v);

		result = sq_call(v, 1, 0, 1);
		sq_pop(v, 1);
		if (SQ_SUCCEEDED(result)) {
			printf("Done! :) \n");
			return 0;
		}
		else {
			printf("Error! :/\n");
		}
	}

	//if this point is reached an error occurred

	const SQChar* err;
	sq_getlasterror(v);
	if (SQ_SUCCEEDED(sq_getstring(v, -1, &err))) {
		scprintf(_SC("Error [%s]\n"), err);
		*retval = -2;
		return _ERROR;
	}


	return _INTERACTIVE;
}

void kill_on_timeout(int sig) {
	if (sig == SIGALRM) {
		printf("[!] Anti DoS Signal. Patch me out for testing.");
		_exit(0);
	}
}



const char* header = "   _____             _               _                        _____                 _          \n"
"  / ____|           (_)             | |                      / ____|               (_)         \n"
" | (___   __ _ _   _ _ _ __ _ __ ___| |   __ _ ___    __ _  | (___   ___ _ ____   ___  ___ ___ \n"
"  \\___ \\ / _` | | | | | '__| '__/ _ \\ |  / _` / __|  / _` |  \\___ \\ / _ \\ '__\\ \\ / / |/ __/ _ \\\n"
"  ____) | (_| | |_| | | |  | | |  __/ | | (_| \\__ \\ | (_| |  ____) |  __/ |   \\ V /| | (_|  __/\n"
" |_____/ \\__, |\\__,_|_|_|  |_|  \\___|_|  \\__,_|___/  \\__,_| |_____/ \\___|_|    \\_/ |_|\\___\\___|\n"
"            | |                                                                                \n"
"            |_|                                                                                \n";

int main(int argc, char* argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	signal(SIGALRM, kill_on_timeout);
	//alarm(60);

	char lenBuffer[128];

	puts(header);
	puts("Execute your squirrel code on this server. Please no coin mining!\n");
	/* puts("Enter code length: "); */

	/* if (read(0, lenBuffer, 16) == -1) */
	/* { */
	/* 	puts("Something went horribly wrong :/\n"); */
	/* 	exit(0); */
	/* } */

	/* unsigned int bufferLen = strtoul(lenBuffer, NULL, 0); */
	/* if (bufferLen > 64*1024) */
	/* { */
	/* 	puts("Nope, to big!\n"); */
	/* 	exit(0); */
	/* } */

	/* puts("Enter Code:"); */

	/* char* bytecode = (char*)malloc(bufferLen); */

	/* int currentLength = 0; */
	/* int lastRead = 0; */
	/* while (currentLength != bufferLen) */
	/* { */
	/* 	lastRead = read(0, bytecode + currentLength, 1); */
	/* 	currentLength += lastRead; */
	/* } */

	printf("[+] Code received. Executing...\n");

	HSQUIRRELVM v;
	SQInteger retval = 0;
#if defined(_MSC_VER) && defined(_DEBUG)
	//_CrtSetAllocHook(MemAllocHook);
#endif

	v = sq_open(1024);
	sq_setprintfunc(v, printfunc, errorfunc);
	sq_pushroottable(v);
	sqstd_register_bloblib(v);
	//sqstd_register_iolib(v);
	//sqstd_register_systemlib(v);
	sqstd_register_mathlib(v);
	sqstd_register_stringlib(v);

	//aux library
	//sets error handlers
	sqstd_seterrorhandlers(v);

	/* char templateFile[] = "/tmp/VMCODE-XXXXXXXX"; */

	/* int filehandle = mkstemp(templateFile); */
	/* write(filehandle, bytecode, bufferLen); */
	/* close(filehandle); */

	//gets arguments
	executeVm(v, &retval, argv[1]);
	//getargs(v, argc, argv, &retval, "/mnt/c/Users/Alain/Downloads/squirrel/git/bin/out2.cnut");

	return 0;
}
