/*
 * QEMU Guest Agent common/cross-platform command implementations
 *
 * Copyright IBM Corp. 2012
 *
 * Authors:
 *  Michael Roth      <mdroth@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "guest-agent-core.h"
#include "qga-qapi-commands.h"
#include "qapi/error.h"
#include "qapi/qmp/qerror.h"
#include "qemu/base64.h"
#include "qemu/cutils.h"
#include "commands-common.h"
#include <pthread.h>
#include <errno.h>

/* Maximum captured guest-exec out_data/err_data - 16MB */
#define GUEST_EXEC_MAX_OUTPUT (16 * 1024 * 1024)
/* Allocation and I/O buffer for reading guest-exec out_data/err_data - 4KB */
#define GUEST_EXEC_IO_SIZE (4 * 1024)
/*
 * Maximum file size to read - 48MB
 *
 * (48MB + Base64 3:4 overhead = JSON parser 64 MB limit)
 */
#define GUEST_FILE_READ_COUNT_MAX (48 * MiB)

/* Note: in some situations, like with the fsfreeze, logging may be
 * temporarilly disabled. if it is necessary that a command be able
 * to log for accounting purposes, check ga_logging_enabled() beforehand,
 * and use the QERR_QGA_LOGGING_DISABLED to generate an error
 */
void slog(const gchar *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	g_logv("syslog", G_LOG_LEVEL_INFO, fmt, ap);
	va_end(ap);
}

int64_t qmp_guest_sync_delimited(int64_t id, Error **errp)
{
	ga_set_response_delimited(ga_state);
	return id;
}

int64_t qmp_guest_sync(int64_t id, Error **errp)
{
	return id;
}

void qmp_guest_ping(Error **errp)
{
	slog("guest-ping called");
}


static void qmp_command_info(const QmpCommand *cmd, void *opaque)
{
	GuestAgentInfo *info = opaque;
	GuestAgentCommandInfo *cmd_info;

	cmd_info = g_new0(GuestAgentCommandInfo, 1);
	cmd_info->name = g_strdup(qmp_command_name(cmd));
	cmd_info->enabled = qmp_command_is_enabled(cmd);
	cmd_info->success_response = qmp_has_success_response(cmd);

	QAPI_LIST_PREPEND(info->supported_commands, cmd_info);
}

struct GuestAgentInfo *qmp_guest_info(Error **errp)
{
	GuestAgentInfo *info = g_new0(GuestAgentInfo, 1);

	info->version = g_strdup(QEMU_VERSION);
	qmp_for_each_command(&ga_commands, qmp_command_info, info);
	return info;
}

struct GuestExecIOData {
	guchar *data;
	gsize size;
	gsize length;
#ifdef G_OS_WIN32
	HANDLE fd;
	HANDLE thread; 
#else
	gint fd;
	pthread_t *thread;
#endif
	bool closed;
	bool truncated;
	const char *name;
	pthread_mutex_t mut;
};
typedef struct GuestExecIOData GuestExecIOData;

struct GuestExecInfo {
	int64_t pid;
#ifdef G_OS_WIN32
	PROCESS_INFORMATION* proc_info;
	DWORD last_exit;
#else
	gint status;
#endif
	bool has_output;
	bool has_input;
	bool finished;
	GuestExecIOData in;
	GuestExecIOData out;
	GuestExecIOData err;
	pthread_mutex_t mut;
	QTAILQ_ENTRY(GuestExecInfo) next;
};
typedef struct GuestExecInfo GuestExecInfo;

static struct {
	QTAILQ_HEAD(, GuestExecInfo) processes;
} guest_exec_state = {
	.processes = QTAILQ_HEAD_INITIALIZER(guest_exec_state.processes),
};

/*
static int64_t gpid_to_int64(GPid pid)
{
#ifdef G_OS_WIN32
	return GetProcessId(pid);
#else
	return (int64_t)pid;
#endif
}
*/
#ifdef G_OS_WIN32
//These are a list of necessary utils copied from ProductLibC

static wchar_t* getCurrentExePath( void ) {
	DWORD sz = 256;
	wchar_t *ourPath = (wchar_t*) malloc( sz * sizeof(wchar_t) );
	if ( ourPath == NULL )
		return NULL;

	/* GetModuleFileName can return more than MAX_PATH, so we
	 must be careful to allocate as much as it wants */

	SetLastError( NO_ERROR );
	GetModuleFileNameW( GetModuleHandle(NULL), ourPath, sz );
	while ( GetLastError() == ERROR_INSUFFICIENT_BUFFER ) {
		free(ourPath);
		sz *= 2;
		ourPath = (wchar_t*) malloc( sz * sizeof(wchar_t) );
		if ( ourPath == NULL )
			return NULL;

		SetLastError( NO_ERROR );
		GetModuleFileNameW( GetModuleHandle(NULL), ourPath, sz );
	};

	if ( GetLastError() == NO_ERROR ) {
		return ourPath;
	} else {
		free(ourPath);
		return NULL;
	}
}

static wchar_t *ConvertUTF8ToWchar( const char *str, size_t *newStrChars ) {

	wchar_t *newstr;
	size_t newstrSize = 0;  /* in characters */

	/* functions below can't handle empty/null strings; shortcut those cases */
	if ( !str )
		return NULL;
	if ( str[0] == '\0' ) {
		newstr = (wchar_t *)malloc(1 * sizeof(wchar_t));
		newstr[0] = L'\0';
		return newstr;
	}

	/* calculate wide-char size */
	newstrSize = MultiByteToWideChar( CP_UTF8, 0, str, -1, NULL, 0 );
	newstr = (wchar_t *)malloc( newstrSize * sizeof(wchar_t) );

	/* do the conversion */
	if ( !MultiByteToWideChar( CP_UTF8, 0, str, -1, newstr, newstrSize ) ) {
		free( newstr );
		return NULL;
	}

	if ( newStrChars )
		*newStrChars = newstrSize;
	return newstr;
}

static wchar_t *escapeArg( const wchar_t *arg ) {
	if ( !arg )
		return NULL;

	size_t len = wcslen(arg);
	size_t tmpLen = len + 3;
	wchar_t *tmp = (wchar_t*) malloc( tmpLen * sizeof(wchar_t) ); /* "arg" */
	if ( tmp == NULL )
		return NULL;
	wchar_t *ret = (wchar_t*) malloc( (len * 3 + 3) * sizeof(wchar_t) );
	if ( ret == NULL ) {
		free(tmp);
		return NULL;
	}
	const wchar_t *src = tmp; /* current src char */
	wchar_t *dst = ret; /* current dst char */

	/* shortcut for case where there are no special characters */
	int foundSpecial = 0;
	const wchar_t *c = arg;
	while ( *c ) {
		if ( !( iswalnum(*c) || (*c == L'.') || (*c == L'-') || (*c == L'/') || (*c == L'\\') || (*c == L':') || (*c == L'_') ) ) {
			foundSpecial = 1;
			break;
		}
		c++;
	}
	if ( !foundSpecial ) {
		free(tmp);
		free(ret);
		return wcsdup(arg);
	}

	/* basic algorithm: surround the arg by "s, then for n
	 (>=0) slashes followed by a ", emit 2n+1 slashes then
	 the " (except for the leading " which doesn't need
	 slashification, and the trailing " which doesn't need
	 it unless the preceding char is a slash... and in that
	 case, use 2n slashes, not 2n+1). */
	swprintf( tmp, tmpLen, L"\"%s\"", arg );

	while ( *src ) {
		if ( *src == L'\\' ) {
			/* double the slash only if there's an upcoming quote
			 with only slashes before it */
			const wchar_t *t = src;
			int foundQuote = 0;
			while ( *t ) {
				if ( *t == L'"' ) {
					foundQuote = 1;
					break;
				} else if ( *t != L'\\' ) {
					break;
				}
				t++;
			}
			if ( foundQuote )
				*dst++ = L'\\';
			*dst++ = *src;

		} else if ( *src == L'"' ) {
			/* add the +1st slash, but no need for the leading "
			 or the ending " (even if there was a (doubled) \
			 in front of it) */
			if ( ( src != tmp ) && ( *(src+1) != L'\0' ) )
				*dst++ = L'\\';
			*dst++ = *src;

		} else {
			*dst++ = *src;
		}

		src++;
	}

	*dst = L'\0';

	free(tmp);

	return ret;
}

static char *ConvertWcharToUTF8( const wchar_t *str, size_t *newStrBytes ) {

	char *newstr;
	size_t newstrSize = 0;  /* in bytes */

	/* functions below can't handle empty/null strings; shortcut those cases */
	if ( !str )
		return NULL;
	if ( str[0] == L'\0' ) {
		newstr = (char *)malloc(1);
		newstr[0] = '\0';
		return newstr;
	}


	/* calculate UTF-8 size */
	newstrSize = WideCharToMultiByte( CP_UTF8, 0, str, -1, NULL, 0,
			NULL, NULL );
	newstr = (char *)malloc( newstrSize );

	/* do the conversion */
	if ( !WideCharToMultiByte( CP_UTF8, 0, str, -1, newstr, newstrSize,
			NULL, NULL ) ) {
		free( newstr );
		return NULL;
	}

	if ( newStrBytes )
		*newStrBytes = newstrSize;
	return newstr;
}

static char *checkedAsprintf( const char *format, ... ) {

	va_list args;
	char *ret = NULL;

	va_list args2;
	int len;

	va_start( args, format );
	va_copy( args2, args );
	len = _vscprintf( format, args2 );
	va_end( args2 );

	if ( len >= 0 ) {
		ret = (char*) malloc(len+1);
		if ( ret == NULL ) {
			fprintf( stderr, "failed to allocate memory when creating a string\n" );
			exit(71); //EX_OSERR from sysexits(3)
		}

		va_start( args, format );
		vsnprintf( ret, len+1, format, args );
		va_end( args );
	} else {
		fprintf( stderr, "failed to determine length when creating a string\n" );
		exit(71); //EX_OSERR from sysexits(3)
	}
	return ret;
}
#endif

static GuestExecInfo *guest_exec_info_add(int64_t pid)
{
	GuestExecInfo *gei;

	gei = g_new0(GuestExecInfo, 1);
	gei->pid = pid;
	pthread_mutex_init(&gei->mut, NULL);
	pthread_mutex_init(&gei->in.mut, NULL);
	pthread_mutex_init(&gei->out.mut, NULL);
	pthread_mutex_init(&gei->err.mut, NULL);
	QTAILQ_INSERT_TAIL(&guest_exec_state.processes, gei, next);

	return gei;
}

static GuestExecInfo *guest_exec_info_find(int64_t pid_numeric)
{
	GuestExecInfo *gei;

	QTAILQ_FOREACH(gei, &guest_exec_state.processes, next) {
		if (gei->pid == pid_numeric) {
			return gei;
		}
	}

	return NULL;
}

//Sends base64-encoded input to the process specified pid stdin
//@param pid - the pid returned by guest exec to send input to
//@param input - the base64 encoded input to send to pid
//@param errp - pointer to return error to if hit
//
//@returns guest exec input struct with a bool to signify whether this was successful
GuestExecSendInput *qmp_guest_exec_send_input(int64_t pid, const char * input, Error **errp)
{
	GuestExecInfo *gei;
	//using a struct to just carry around a bool is dumb but it seems better to set this
	//up now so additions are easier and to be consistent 
	GuestExecSendInput *gesi; 

	slog("guest-exec-send-input, pid: %u", (uint32_t) pid);

	gesi = g_new0(GuestExecSendInput, 1);
	gesi->success = false;

	gei = guest_exec_info_find(pid);
	if(gei == NULL){
		slog("gesi: couldn't find pid");
		error_setg(errp, QERR_INVALID_PARAMETER, "pid");
		return gesi;
	}

	pthread_mutex_lock(&gei->mut);
	
#ifdef G_OS_WIN32
	//we always set this up for windows so a meaningless check
	bool validFd = true;
#else
	GError* err = NULL;
	bool validFd = gei->in.fd >= 0;
#endif

	if(gei->finished || !gei->has_input || !validFd){   
		pthread_mutex_unlock(&gei->mut);
		slog("gesi: process exited or in does not have valid fd");
		error_setg(errp, QERR_IO_ERROR);
		return gesi;
	}
	pthread_mutex_unlock(&gei->mut);

	
	//gsize bytes_written;

	g_autofree uint8_t * dec_in = NULL;
	size_t ninput = 0;
	dec_in  = qbase64_decode(input, -1, &ninput, errp);
	if (!dec_in) {
		slog("gesi: could not decode input");
		error_setg(errp, QERR_IO_ERROR);
		return gesi;
	}

#ifdef G_OS_WIN32

	DWORD numWritten;
	WriteFile(gei->in.fd, dec_in, ninput, &numWritten, NULL);
	if(numWritten != (DWORD)ninput){
		slog("Only wrote %d bytes to stdin of message of length %d", (int)numWritten, (int)ninput);
	}
	else{
		gesi->success = true;
	}
#else
	size_t amt_written = 0;
	while(amt_written != ninput){
		//status = g_io_channel_write_chars(gei->in.channel, (gchar *)(dec_in + amt_written),
		//      ninput, &bytes_written, &err);
		int bytes_written = write(gei->in.fd, dec_in + amt_written, ninput);    
		if (bytes_written < 0) {
			slog("gesi: error writing to input_data channel: %d, fd was %d", errno, gei->in.fd);
			g_warning("qga: i/o error writing to input_data channel: %s",
					err->message);
			error_setg(errp, QERR_IO_ERROR);
			return gesi;
		}
		else{
			amt_written += bytes_written;
		}
	}
	gesi->success = (amt_written == ninput);
#endif
	return gesi;

}


//checks for any available input on process pid and returns the exit status
//if pid has exited
//
//@param pid the pid returned by guest exec to check
//@returns guest exec status struct with the output data and exit status if any
GuestExecStatus *qmp_guest_exec_status(int64_t pid, Error **errp)
{
	GuestExecInfo *gei;
	GuestExecStatus *ges;

	slog("guest-exec-status called, pid: %u", (uint32_t)pid);

	gei = guest_exec_info_find(pid);
	if (gei == NULL) {
		error_setg(errp, QERR_INVALID_PARAMETER, "pid");
		return NULL;
	}

	ges = g_new0(GuestExecStatus, 1);

	pthread_mutex_lock(&gei->mut);
	bool finished = gei->finished;

	ges->exited = finished;
	if (finished) {
		if(gei->out.thread != NULL){
#ifdef G_OS_WIN32
			WaitForSingleObject(gei->out.thread, 5000);
#else
			pthread_join(*(gei->out.thread), NULL);
#endif
		}
		/* Glib has no portable way to parse exit status.
		 * On UNIX, we can get either exit code from normal termination
		 * or signal number.
		 * On Windows, it is either the same exit code or the exception
		 * value for an unhandled exception that caused the process
		 * to terminate.
		 * See MSDN for GetExitCodeProcess() and ntstatus.h for possible
		 * well-known codes, e.g. C0000005 ACCESS_DENIED - analog of SIGSEGV
		 * References:
		 *   https://msdn.microsoft.com/en-us/library/windows/desktop/ms683189(v=vs.85).aspx
		 *   https://msdn.microsoft.com/en-us/library/aa260331(v=vs.60).aspx
		 */
#ifdef G_OS_WIN32
		/* Additionally WIN32 does not provide any additional information
		 * on whether the child exited or terminated via signal.
		 * We use this simple range check to distinguish application exit code
		 * (usually value less then 256) and unhandled exception code with
		 * ntstatus (always value greater then 0xC0000005). */
		if ((uint32_t)gei->last_exit < 0xC0000000U) {
			ges->has_exitcode = true;
			ges->exitcode = gei->last_exit;
		} else {
			ges->has_signal = true;
			ges->signal = gei->last_exit;
		}
#else
		if (WIFEXITED(gei->status)) {
			ges->has_exitcode = true;
			ges->exitcode = WEXITSTATUS(gei->status);
		} else if (WIFSIGNALED(gei->status)) {
			ges->has_signal = true;
			ges->signal = WTERMSIG(gei->status);
		}
#endif
		pthread_mutex_lock(&gei->out.mut);
		if (gei->out.length > 0) {
			ges->has_out_data = true;
			ges->out_data = g_base64_encode(gei->out.data, gei->out.length);
			g_free(gei->out.data);
			ges->has_out_truncated = gei->out.truncated;
		}
		pthread_mutex_destroy(&gei->out.mut);
		pthread_mutex_lock(&gei->err.mut);
		if (gei->err.length > 0) {
			ges->has_err_data = true;
			ges->err_data = g_base64_encode(gei->err.data, gei->err.length);
			g_free(gei->err.data);
			ges->has_err_truncated = gei->err.truncated;
		}
		pthread_mutex_destroy(&gei->err.mut);
		pthread_mutex_destroy(&gei->mut);
		QTAILQ_REMOVE(&guest_exec_state.processes, gei, next);
		g_free(gei);
	}
	else{
		pthread_mutex_lock(&gei->out.mut);
		if(gei->out.length > 0){
			ges->has_out_data = true;
			ges->out_data = g_base64_encode(gei->out.data, gei->out.length);
			memset(gei->out.data, 0, (gei->out.size) * sizeof(guchar));
			gei->out.length = 0;
		}
		pthread_mutex_unlock(&gei->out.mut);    
	}
	pthread_mutex_unlock(&gei->mut);

	return ges;
}

/* Get environment variables or arguments array for execve(). */
static char **guest_exec_get_args(const strList *entry, bool log)
{
	const strList *it;
	int count = 1, i = 0;  /* reserve for NULL terminator */
	char **args;
	char *str; /* for logging array of arguments */
	size_t str_size = 1;

	for (it = entry; it != NULL; it = it->next) {
		count++;
		str_size += 1 + strlen(it->value);
	}

	str = g_malloc(str_size);
	*str = 0;
	args = g_new(char *, count);
	for (it = entry; it != NULL; it = it->next) {
		args[i++] = it->value;
		pstrcat(str, str_size, it->value);
		if (it->next) {
			pstrcat(str, str_size, " ");
		}
	}
	args[i] = NULL;

	if (log) {
		slog("guest-exec called: \"%s\"", str);
	}
	g_free(str);

	return args;
}

#ifdef G_OS_WIN32
//this just waits on the pid to grab the exit code
static DWORD WINAPI guest_exec_wait( LPVOID lpParameter ){
	slog("guest_exec_wait called");
	int64_t pid = *(int64_t*) (lpParameter);
	DWORD dwResult; 
	GuestExecInfo *gei;
	gei = guest_exec_info_find(pid);
	if(gei == NULL){
		slog("could not wait on this pid: %d", (int)pid);
		return -1;
	}   
	slog("found gei for pid: %d", (int)pid);
	if((dwResult = WaitForSingleObject(gei->proc_info->hProcess, INFINITE)) != WAIT_OBJECT_0){
		slog("wait was unsucessfull");
	}
	pthread_mutex_lock(&gei->mut);
	if (dwResult == WAIT_FAILED) {
		gei->last_exit = -1; 
	} else {
		GetExitCodeProcess( gei->proc_info->hProcess, &gei->last_exit);
		CloseHandle( gei->proc_info->hThread );
		CloseHandle( gei->proc_info->hProcess );
		gei->proc_info->hThread = INVALID_HANDLE_VALUE;
		gei->proc_info->hProcess = INVALID_HANDLE_VALUE;
	}
	gei->finished = true;
	gei->out.closed = true;
	gei->in.closed = true;
	gei->err.closed = true; 

	pthread_mutex_unlock(&gei->mut);
	return 0;

}
#else
//this just waits on the pid to grab the exit code
static void* guest_exec_wait(void * arg){
	slog("guest_exec_wait called");
	int64_t pid = *(int64_t*) (arg);
	GuestExecInfo * gei;
	gei = guest_exec_info_find(pid);
	if(gei == NULL){
	   slog("could not wait on this pid: %d", (int)pid);
	   return NULL;
	}
	slog("found gei for pid: %d", (int)pid);
	int status;
	waitpid(pid, &status, 0);  
	pthread_mutex_lock(&gei->mut);
	gei->status = status;
	gei->finished = true;
	gei->out.closed = true;
	gei->err.closed = true;
	gei->in.closed = true;
	pthread_mutex_unlock(&gei->mut);
	slog("guest_exec_wait returning successfully");
   return NULL; 
}
#endif

#ifdef G_OS_WIN32
//thread to grab output from pid and write to buffer in real-time
static DWORD WINAPI guest_exec_output( LPVOID lpParameter ){
	slog("guest_exec_output called");
	int64_t pid = *(int64_t*) (lpParameter);
	GuestExecInfo *gei;
	gei = guest_exec_info_find(pid);
	if(gei == NULL){
		slog("could not wait on this pid: %d", (int)pid);
		return -1;
	}
	slog("found gei for pid: %d", (int)pid);

	char buf[1];
	DWORD numRead;
	DWORD bufferLength = 1;
	memset( buf, 0, bufferLength );
	//grabbing finished w/o mutex because I'm not changing it & once it's set, it's not going to change
	while ( ReadFile(gei->out.fd, buf, bufferLength, &numRead, NULL) && numRead && !gei->finished) {
		pthread_mutex_lock(&gei->out.mut);
		//try to resize the buffer if necessary
		if (gei->out.size == gei->out.length) {
			gpointer t = NULL;
			if (!gei->out.truncated && gei->out.size < GUEST_EXEC_MAX_OUTPUT) {
				t = g_try_realloc(gei->out.data, gei->out.size + GUEST_EXEC_IO_SIZE);
			}
			if (t == NULL) {
				/* ignore truncated output */
				gei->out.truncated = true;
				pthread_mutex_unlock(&gei->out.mut);
				break;
			}
			gei->out.size += GUEST_EXEC_IO_SIZE;
			gei->out.data = t;
		}
		memcpy(gei->out.data + gei->out.length, buf, numRead*sizeof(char));
		gei->out.length += numRead;
		pthread_mutex_unlock(&gei->out.mut);
		memset( buf, 0, bufferLength );
	}

	CloseHandle(gei->out.fd);
	return 0;
}
#else
//thread to grab output from pid and write to buffer
static void*  guest_exec_output(void * arg){
	slog("guest_exec_output called");
	GuestExecIOData* geio = (GuestExecIOData*)arg;
	int out_fd = (int)geio->fd;
	fd_set rfd;
	do{
		struct timeval tv = {0};
		tv.tv_sec = 0;
		tv.tv_usec = 10;

		FD_ZERO(&rfd);
		FD_SET(out_fd, &rfd);

		int retval = select(out_fd+1, &rfd, NULL, NULL, &tv);
		if(retval < 0){
			slog("select returned < 0");
			break;
		}
		if(FD_ISSET(out_fd, &rfd)){
			int nread;
			char buf[1025] = {0};
			if( (nread = read(out_fd, buf, 1024)) > 0){
				slog("got output now writing to struct buffer");
				//now write to a global buffer
				pthread_mutex_lock(&geio->mut); 
				//try to resize the buffer if necessary
				if (geio->size == geio->length) {
					gpointer t = NULL;
					if (!geio->truncated && geio->size < GUEST_EXEC_MAX_OUTPUT) {
						t = g_try_realloc(geio->data, geio->size + GUEST_EXEC_IO_SIZE);
					}
					if (t == NULL) {
						/* ignore truncated output */
						geio->truncated = true;
						pthread_mutex_unlock(&geio->mut);
						break;
					}
					geio->size += GUEST_EXEC_IO_SIZE;
					geio->data = t;
				}
				memcpy(geio->data + geio->length, buf, nread*sizeof(char));
				geio->length += nread;
				pthread_mutex_unlock(&geio->mut);   
			}
			else if(nread < 0){
				slog("read returned with error code %d", nread); 
				break;
			}
			else{
				break;
				slog("read returned 0");
			}
		}       
	}while(!geio->closed);
	pthread_mutex_lock(&geio->mut);
	geio->thread = NULL;
	pthread_mutex_unlock(&geio->mut);
	return NULL;
}
#endif

//executes binary and path and returns a struct with the pid
GuestExec *qmp_guest_exec(const char *path,
					   bool has_arg, strList *arg,
					   bool has_env, strList *env,
					   bool has_using_input, bool using_input,
					   bool has_capture_output, bool capture_output,
					   Error **errp)
{
	GuestExec *ge = NULL;
	GuestExecInfo *gei;
	//char **argv, **envp;
	char **argv;
	strList arglist;
	bool has_input = (has_using_input && using_input);
	bool has_output = (has_capture_output && capture_output);


	arglist.value = (char *)path;
	arglist.next = has_arg ? arg : NULL;

	argv = guest_exec_get_args(&arglist, true);
	//windows currently not supporting environment variable
	//envp = has_env ? guest_exec_get_args(env, false) : NULL;
#ifdef G_OS_WIN32

	HANDLE hStdIn[2];
	HANDLE hStdOut[2];
	HANDLE hStdErr[2];
	PROCESS_INFORMATION * pi_pt = malloc(sizeof(PROCESS_INFORMATION));

#define PIPE_READ(hPipe) hPipe[0]
#define PIPE_WRITE(hPipe) hPipe[1]

	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof (SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if ( !CreatePipe(&PIPE_READ(hStdOut), &PIPE_WRITE(hStdOut), &saAttr, 1) ) {
		slog( "Could not create a pipe for child process's stdout");
		error_setg(errp, "Could not create stdout pipe");
		return NULL;
	}
	SetHandleInformation( PIPE_READ(hStdOut), HANDLE_FLAG_INHERIT, 0 );

	if ( !CreatePipe(&PIPE_READ(hStdErr), &PIPE_WRITE(hStdErr), &saAttr, 1)) {
		slog( "Could not create a pipe for child process's stderr");
		error_setg(errp, "Could not create stderr pipe");
		return NULL;
	}
	SetHandleInformation( PIPE_READ(hStdErr), HANDLE_FLAG_INHERIT, 0 );

	if ( !CreatePipe(&PIPE_READ(hStdIn), &PIPE_WRITE(hStdIn), &saAttr, 1) ) {
		slog( "Could not create a pipe for child process's stdin");
		error_setg(errp, "Could not create Stdin pipe");
		return NULL;
	}
	SetHandleInformation( PIPE_WRITE(hStdIn), HANDLE_FLAG_INHERIT, 0);

	//RunCommand
	//BuildCommandString
	char *ret = strdup("");


	int i;
	for (i = 0 ; argv[i] != NULL ; ++i) {
		const char *arg = argv[i];
		wchar_t *argW = ConvertUTF8ToWchar( arg, NULL );
		if ( argW ) {
			wchar_t *argWE = escapeArg( argW );
			if ( argWE ) {
				char *argWEU = ConvertWcharToUTF8( argWE, NULL );
				if ( argWEU ) {
					char *ret2 = checkedAsprintf( "%s%s%s", ret, (ret[0] ? " " : ""), argWEU );
					free(ret);
					ret = ret2;
					free(argWEU);
				}
				free(argWE);
			}
			free(argW);
		}
	}

	//end BuildCommandString
	char* commandLine = ret;
	if (!commandLine) {
		slog( "Could not build the command line!" );
		error_setg(errp, "Could not build command line");
		return NULL;
	}
	//slog("Command line: %s", commandLine);
	wchar_t *commandLineW = ConvertUTF8ToWchar( commandLine, NULL );
	free(commandLine);

	// make the working directory be that containing our executable
	wchar_t *workingDir = getCurrentExePath();
	if ( !workingDir ) {
		slog( "Could not get current executable path" );
		error_setg(errp, "Failed to make working directory");
		return NULL;
	}
	wchar_t *dirsep = wcsrchr( workingDir, L'\\' );
	if ( !dirsep ) {
		slog( "Could not get current executable path parent directory." );
		error_setg(errp, "Faied to get directory");
		return NULL;
	}
	*dirsep = L'\0';

	ZeroMemory( pi_pt, sizeof(PROCESS_INFORMATION) );

	STARTUPINFOW startupInformation = {0};
	startupInformation.cb = sizeof (STARTUPINFOW);
	startupInformation.hStdError = PIPE_WRITE(hStdErr);
	startupInformation.hStdOutput = PIPE_WRITE(hStdOut);
	startupInformation.hStdInput = PIPE_READ(hStdIn);
	startupInformation.dwFlags |= STARTF_USESTDHANDLES;

	HANDLE hJob = CreateJobObject(NULL, NULL);
	if (hJob) {
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobinfo = { 0 };
		jobinfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
		SetInformationJobObject( hJob, JobObjectExtendedLimitInformation, &jobinfo, sizeof(jobinfo) );
	} else {
		slog( "Could not create job object" );
	}
	
	SetLastError(ERROR_SUCCESS);
	BOOL rc = CreateProcessW( NULL,     /* app name, NULL just means it takes the whole command line from the next argument */
		commandLineW,  /* command (in quotes) with all arguments */
		NULL,     /* process attributes, NULL means the process handle can't be inherited */
		NULL,     /* thread attributes, NULL means the thread handle can't be inherited */
		TRUE,     /* inherit handles: each inheritable handle in the calling process is inherited by the new process*/
		0,        /* creation flags; specifically, we _don't_ want to create a new console window */
		NULL,     /* environment, NULL means the child process uses its parent's environment */
		workingDir,     /* current directory */
		&startupInformation,
		pi_pt );

	DWORD dwErrorCode = GetLastError();
	if (rc) {
		slog( "Child process started" );
		if (hJob) {
			if (!AssignProcessToJobObject(hJob, pi_pt->hProcess)) {
				slog( "Could not add process to job object");
			}
		}

		CloseHandle( PIPE_READ(hStdIn) );
		CloseHandle( PIPE_WRITE(hStdOut) );
		CloseHandle( PIPE_WRITE(hStdErr) );
	} else {
		slog( "Failed to create child process");
	}

	free(commandLineW);
	free(workingDir);
	SetLastError(dwErrorCode);
	//End RunCommand
	if ( !rc ) {
		error_setg(errp, "RunCommand failed!");
		return NULL;
	} else {
		ge = g_new0(GuestExec, 1);
		ge->pid = (int64_t)pi_pt->dwProcessId;
		
		gei = guest_exec_info_add((int64_t)pi_pt->dwProcessId);
		gei->proc_info = pi_pt;
		pthread_mutex_lock(&gei->mut);
		gei->has_output = has_output;
		gei->has_input = has_input;
		gei->in.fd = PIPE_WRITE(hStdIn);
		gei->in.closed = false;
		gei->out.fd = PIPE_READ(hStdOut);
		gei->out.closed = false;
		gei->err.fd = PIPE_READ(hStdErr);
		gei->err.closed = false;

		gei->out.thread = CreateThread( NULL, 0, guest_exec_output, &gei->pid, 0, NULL);
		CreateThread(NULL, 0 , guest_exec_wait, &gei->pid, 0, NULL);
	}

#undef PIPE_READ
#undef PIPE_WRITE

#else
	char **envp;
	envp = has_env ? guest_exec_get_args(env, false) : NULL;
	pthread_t outputThread, waitThread;
#define PIPE_READ 0
#define PIPE_WRITE 1
	int childIn[2];
	int childOut[2];
	int childErr[2];

	/*
	the child process closes the PIPE_READ side.
	the parent closes the PIPE_WRITE

	flip that for stdin
	*/
	if(pipe( childIn ) < 0){
		error_setg(errp, QERR_IO_ERROR);
		return NULL;
	}
	if(pipe( childOut ) < 0){
		error_setg(errp, QERR_IO_ERROR);
		return NULL;
	}
	if(pipe( childErr ) < 0){
		error_setg(errp, QERR_IO_ERROR);
		return NULL;
	}

	pid_t pid = fork();
	if ( pid == 0 ) {
		/* in the child process */
		setvbuf(stdout, NULL, _IONBF, 0);
		close(childIn[PIPE_WRITE]);
		close(childOut[PIPE_READ]);
		close(childErr[PIPE_READ]);

		//make stdin == the pipes' read end
		dup2(childIn[PIPE_READ], 0);

		// make stdout/estdrr == the pipes' write end
		dup2(childOut[PIPE_WRITE], 1);
		dup2(childErr[PIPE_WRITE], 2);

		// make sure the other end of the pipes is closed on exec;
		if ( fcntl(childIn[PIPE_READ], F_SETFD, FD_CLOEXEC) == -1 ) {
			slog( "Failed to set close-on-exec for read side of childIn pipe");
		}
		if ( fcntl(childOut[PIPE_WRITE], F_SETFD, FD_CLOEXEC) == -1 ) {
			slog( "Failed to set close-on-exec for write side of childOut pipe" );
		}
		if ( fcntl(childErr[PIPE_WRITE], F_SETFD, FD_CLOEXEC) == -1 ) {
			slog( "Failed to set close-on-exec for write side of childErr pipe" );
		}

		//build correct arg structure for stdbuf
		//if stdbuf is there, we're using it. Otherwise, we're directly execing it,
		//and the user will have to deal with buffering if present
		char stdbuf[] = "/bin/stdbuf";
		if(access(stdbuf, F_OK) == 0){
			int init_argc = 0;
			while(argv[init_argc] != NULL) init_argc++; 
			//adding 1 to get to the size of the argv array
			//then 1 for stdbuf and 1 for the stdbuf option
			init_argc+=3;

			char stdbuf_opt[] = "-o0";
			char * args[init_argc];
			args[0] = stdbuf;
			args[1] = stdbuf_opt;
			for(int i = 2; i < init_argc; i++){
				args[i] = argv[i-2];
			}
			// execute the command; this only returns on failure
			if(has_env){
				slog("executing w/environment vars");
				execve(args[0], args, envp);
			}
			else{
				slog("executing w/o environment vars");
				execv(args[0], args);
			}
		else{
			if(has_env){
				slog("executing w/env vars");
				execve(argv[0], argv, envp);
			}
			else{
				slog("executing w/o env vars");
				execv(argv[0], argv);
			}
		}
		
		slog("guest-exec failed to execute command");
		close( childIn[PIPE_READ] );
		close( childOut[PIPE_WRITE] );
		close( childErr[PIPE_WRITE] );
		return NULL;
		}

	} else {
		/* still in the original process */

		/* saves me constantly typing out the whole array thing.. */
		int in = childIn[PIPE_WRITE];
		int out = childOut[PIPE_READ];
		int err = childErr[PIPE_READ];

		//gChildPid = pid;
		ge = g_new0(GuestExec, 1);
		ge->pid = pid;

		gei = guest_exec_info_add(pid);
		pthread_mutex_lock(&gei->mut);
		gei->has_output = has_output;
		gei->has_input = has_input;

		close( childIn[PIPE_READ] );
		close( childOut[PIPE_WRITE] );
		close( childErr[PIPE_WRITE] );

		gei->in.closed = false;
		gei->out.closed = false;
		gei->err.closed = false;

		if (has_input) {
			gei->in.fd = in;
		}
		if (has_output) {
			//probably have to duplicate this for err
			gei->out.fd = out;
			slog("spawning outputThread");
			pthread_create(&outputThread, NULL, &guest_exec_output, (void *) &gei->out);
			gei->out.thread = &outputThread;
			gei->err.fd = err;
		}
		slog("spawning waitThread");
		pthread_create(&waitThread, NULL, &guest_exec_wait, (void *) &gei->pid);
	}
#undef PIPE_READ
#undef PIPE_WRITE
	g_free(envp);
#endif
	g_free(argv);
	pthread_mutex_unlock(&gei->mut);
	slog("guest-exec exiting");

	return ge;
}

/* Convert GuestFileWhence (either a raw integer or an enum value) into
 * the guest's SEEK_ constants.  */
int ga_parse_whence(GuestFileWhence *whence, Error **errp)
{
	/*
	 * Exploit the fact that we picked values to match QGA_SEEK_*;
	 * however, we have to use a temporary variable since the union
	 * members may have different size.
	 */
	if (whence->type == QTYPE_QSTRING) {
		int value = whence->u.name;
		whence->type = QTYPE_QNUM;
		whence->u.value = value;
	}
	switch (whence->u.value) {
		case QGA_SEEK_SET:
			return SEEK_SET;
		case QGA_SEEK_CUR:
			return SEEK_CUR;
		case QGA_SEEK_END:
			return SEEK_END;
	}
	error_setg(errp, "invalid whence code %"PRId64, whence->u.value);
	return -1;
}

GuestHostName *qmp_guest_get_host_name(Error **errp)
{
	GuestHostName *result = NULL;
	g_autofree char *hostname = qga_get_host_name(errp);

	/*
	 * We want to avoid using g_get_host_name() because that
	 * caches the result and we wouldn't reflect changes in the
	 * host name.
	 */

	if (!hostname) {
		hostname = g_strdup("localhost");
	}

	result = g_new0(GuestHostName, 1);
	result->host_name = g_steal_pointer(&hostname);
	return result;
}

GuestTimezone *qmp_guest_get_timezone(Error **errp)
{
	GuestTimezone *info = NULL;
	GTimeZone *tz = NULL;
	gint64 now = 0;
	gint32 intv = 0;
	gchar const *name = NULL;

	info = g_new0(GuestTimezone, 1);
	tz = g_time_zone_new_local();
	if (tz == NULL) {
		error_setg(errp, QERR_QGA_COMMAND_FAILED,
				   "Couldn't retrieve local timezone");
		goto error;
	}

	now = g_get_real_time() / G_USEC_PER_SEC;
	intv = g_time_zone_find_interval(tz, G_TIME_TYPE_UNIVERSAL, now);
	info->offset = g_time_zone_get_offset(tz, intv);
	name = g_time_zone_get_abbreviation(tz, intv);
	if (name != NULL) {
		info->has_zone = true;
		info->zone = g_strdup(name);
	}
	g_time_zone_unref(tz);

	return info;

error:
	g_free(info);
	return NULL;
}

GuestFileRead *qmp_guest_file_read(int64_t handle, bool has_count,
								   int64_t count, Error **errp)
{
	GuestFileHandle *gfh = guest_file_handle_find(handle, errp);
	GuestFileRead *read_data;

	if (!gfh) {
		return NULL;
	}
	if (!has_count) {
		count = QGA_READ_COUNT_DEFAULT;
	} else if (count < 0 || count > GUEST_FILE_READ_COUNT_MAX) {
		error_setg(errp, "value '%" PRId64 "' is invalid for argument count",
				   count);
		return NULL;
	}

	read_data = guest_file_read_unsafe(gfh, count, errp);
	if (!read_data) {
		slog("guest-file-write failed, handle: %" PRId64, handle);
	}

	return read_data;
}

int64_t qmp_guest_get_time(Error **errp)
{
	return g_get_real_time() * 1000;
}
