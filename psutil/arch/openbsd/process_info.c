/*
 * $Id: process_info.c 1187 2011-10-22 15:56:59Z g.rodola $
 *
 * Copyright (c) 2009, Jay Loden, Giampaolo Rodola'. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Helper functions related to fetching process information. Used by _psutil_bsd
 * module methods.
 */

#include <Python.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <signal.h>
#include <kvm.h>

#include "process_info.h"



/*
 * Returns a list of all BSD processes on the system.  This routine
 * allocates the list and puts it in *procList and a count of the
 * number of entries in *procCount.  You are responsible for freeing
 * this list (use "free" from System framework).
 * On success, the function returns 0.
 * On error, the function returns a BSD errno value.
 */
int
get_proc_list(struct kinfo_proc **procList, size_t *procCount)
{
    static const int name[] = { CTL_KERN, KERN_PROC, KERN_PROC, 0 };
    // Declaring name as const requires us to cast it when passing it to
    // sysctl because the prototype doesn't include the const modifier.
    char errbuf[_POSIX2_LINE_MAX];
    struct kinfo_proc *result;
    struct kinfo_proc *x;
    int cnt;
    kvm_t *kd;

    assert( procList != NULL);
    assert(*procList == NULL);
    assert(procCount != NULL);

    kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf);

    if (kd == NULL) {
        fprintf(stderr, "WWWWWWWWWWWWWWWWWW\n");
        return errno;
    }

    result = kvm_getprocs(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc), &cnt);
    if (result == NULL) {
        fprintf(stderr, "UUUUUUUUUUUUUUUUUU\n");
        err(1, NULL);
        return errno;
    }

    *procCount = (size_t)cnt;

    size_t mlen = cnt * sizeof(struct kinfo_proc);

    if ((*procList = malloc(mlen)) == NULL) {
        fprintf(stderr, "ZZZZZZZZZZZZZZZZZZ\n");
        err(1, NULL);
        return errno;
    }

    memcpy(*procList, result, mlen);

    assert(*procList != NULL);

    kvm_close(kd);

    return 0;
}


char
*getcmdpath(long pid, size_t *pathsize)
{
    int  mib[4];
    char *path;
    size_t size = 0;

    /*
     * Make a sysctl() call to get the raw argument space of the process.
     */
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_ARGS;
    mib[3] = pid;

    // call with a null buffer first to determine if we need a buffer
    if (sysctl(mib, 4, NULL, &size, NULL, 0) == -1) {
        return NULL;
    }

    path = malloc(size);
    if (path == NULL)
        return NULL;

    *pathsize = size;
    if (sysctl(mib, 4, path, &size, NULL, 0) == -1) {
        free(path);
        return NULL;       /* Insufficient privileges */
    }

    return path;
}

char **
get_argv(long pid)
{
    static char **argv;
    char **p;
    int argv_mib[] = {CTL_KERN, KERN_PROC_ARGS, pid, KERN_PROC_ARGV};
    size_t argv_size = 128;

    /* Loop and reallocate until we have enough space to fit argv. */
    for (;; argv_size *= 2) {
        if ((argv = realloc(argv, argv_size)) == NULL)
            err(1, NULL);

        if (sysctl(argv_mib, 4, argv, &argv_size, NULL, 0) == 0)
            break;

        if (errno == ESRCH) {
            PyErr_SetFromErrno(PyExc_OSError);
            return NULL;
        }

        if (errno != ENOMEM)
            err(1, NULL);
    }

    return argv;
}


/* returns the command line as a python list object */
PyObject*
get_arg_list(long pid)
{
    static char **argv;
    char **p;
    PyObject *retlist = Py_BuildValue("[]");
    PyObject *item = NULL;

    // XXX: why not error out?!
    if (pid < 0)
        return retlist;

    if ((argv = get_argv(pid)) == NULL)
        return NULL;

    for (p = argv; *p != NULL; p++) {
	item = Py_BuildValue("s", *p);
	PyList_Append(retlist, item);
	Py_DECREF(item);
    }

    // XXX: free argv?

    return retlist;
}

/* returns the command line as a python list object */
PyObject *
get_progname(long pid)
{
    static char **argv;
    char buf[MAXPATHLEN];

    if (pid < 0)
	return NULL;

    if ((argv = get_argv(pid)) == NULL) {
        return NULL;
    }

    strlcpy(buf, argv[0], MAXPATHLEN);

    return Py_BuildValue("s", buf);
}


/*
 * Return 1 if PID exists in the current process list, else 0.
 */
int
pid_exists(long pid)
{
    int kill_ret;
    if (pid < 0) {
        return 0;
    }

    // if kill returns success of permission denied we know it's a valid PID
    kill_ret = kill(pid , 0);
    if ((0 == kill_ret) || (EPERM == errno)) {
        return 1;
    }

    // otherwise return 0 for PID not found
    return 0;
}

