/*
** yp_tconf.c - derived from...
** yp_passwd.c           NIS Version 2 Passwd map access routines
**
** Copyright (c) 1993 Signum Support AB, Sweden
**
** This file is part of the NYS Library.
**
** The NYS Library is free software; you can redistribute it and/or
** modify it under the terms of the GNU Library General Public License as
** published by the Free Software Foundation; either version 2 of the
** License, or (at your option) any later version.
**
** The NYS Library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Library General Public License for more details.
** 
** You should have received a copy of the GNU Library General Public
** License along with the NYS Library; see the file COPYING.LIB.  If
** not, write to the Free Software Foundation, Inc., 675 Mass Ave,
** Cambridge, MA 02139, USA.
**
** Author: Peter Eriksson <pen@signum.se>
*/

#include "config.h"
#include "nys_config.h"

#ifdef ENABLE_YP


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "t_pwd.h"
#include "yp_misc.h"
#include "cstr.h"
#include <rpcsvc/ypclnt.h>

static int rewind_flag = 1;
static char *savekey = NULL;
static int savekeylen = 0;


static struct t_confent *tcent_parse(char *str, int len)
{
    static struct t_conf tc;
    char *cp;

    if(tc.modbuf == NULL)
      tc.modbuf = cstr_new();
    if(tc.genbuf == NULL)
      tc.genbuf = cstr_new();

    cp   = _yp_xstrtok(str, ':');
    if (cp == NULL)
	return NULL;
    tc.tcbuf.index = atoi(cp);
    
    cp = _yp_xstrtok(NULL, ':');
    if (cp == NULL)
	return NULL;
    tc.tcbuf.modulus.len = t_cstrfromb64(tc.modbuf, cp);
    if(tc.tcbuf.modulus.len <= 0)
        return NULL;
    tc.tcbuf.modulus.data = tc.modbuf->data;
    
    cp = _yp_xstrtok(NULL, ':');
    if (cp == NULL)
	return NULL;
    tc.tcbuf.generator.len = t_cstrfromb64(tc.genbuf, cp);
    if(tc.tcbuf.generator.len <= 0)
        return NULL;
    tc.tcbuf.generator.data = tc.genbuf->data;

    return &tc.tcbuf;
}


void _yp_settcent(void)
{
    rewind_flag = 1;
    if (savekey)
	free(savekey);
}


void _yp_endtcent(void)
{
    rewind_flag = 1;
    if (savekey)
	free(savekey);
}


struct t_confent *_yp_gettcent(void)
{
    struct t_confent *tcent;
    char *map;
    char *domain;
    char *result;
    int len;
    char *outkey;
    int keylen;


    map = _ypopts_getmd("tconf", ".byid", &domain);
    if (map == NULL)
	return NULL;

    tcent = NULL;
    
    if (rewind_flag)
    {
	if (yp_first(domain, map,
		     &outkey, &keylen,
		     &result, &len))
	    goto error;
	
	rewind_flag = 0;
	savekey = outkey;
	savekeylen = keylen;
    }
    else
    {
	if (yp_next(domain, map,
		    savekey, savekeylen, &outkey, &keylen,
		    &result, &len))
	    goto error;
	
	free(savekey);
	savekey = outkey;
	savekeylen = keylen;
    }

    /*
    ** Loop, fetching the next entry if there is an incorrectly
    ** formatted entry.
    */
    errno = 0;
    while ((tcent = tcent_parse(result, len)) == NULL && errno == 0)
    {
#ifdef DEBUG
	fprintf(stderr, "yp_tconf: Invalid conf entry: %.*s\n",
		len, result);
#endif
	free(result);
	
	if (yp_next(domain, map,
		    savekey, savekeylen, &outkey, &keylen,
		    &result, &len))
	    goto error;
	
	free(savekey);
	savekey = outkey;
	savekeylen = keylen;
    }
    
    free(result);

  error:
    free(map);
    free(domain);
    
    return tcent;
}


struct t_confent *_yp_gettcid(int id)
{
    struct t_confent *tcent;
    char *map;
    char *domain;
    char *result;
    int len;
    char buf[16];

    map = _ypopts_getmd("tconf", ".byid", &domain);
    if (map == NULL)
	return NULL;

    sprintf(buf, "%u", id);

    tcent = NULL;
    
    if (yp_match(domain, map, buf, strlen(buf), &result, &len) == 0)
    {
	tcent = tcent_parse(result, len);
	free(result);
    }

    free(map);
    free(domain);
    
    return tcent;
}

#endif /* ENABLE_YP */
