/*
** yp_tpasswd.c - derived from...
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
#include <rpcsvc/ypclnt.h>

static int rewind_flag = 1;
static char *savekey = NULL;
static int savekeylen = 0;

static struct t_passwd tpass;

static void
pwsetup(out, tpwd, tcnf)
     struct t_passwd * out;
     struct t_pwent * tpwd;
     struct t_confent * tcnf;
{
  out->tp.name = tpwd->name;
  out->tp.password.len = tpwd->password.len;
  out->tp.password.data = tpwd->password.data;
  out->tp.salt.len = tpwd->salt.len;
  out->tp.salt.data = tpwd->salt.data;
  out->tp.index = tpwd->index;

  out->tc.index = tcnf->index;
  out->tc.modulus.len = tcnf->modulus.len;
  out->tc.modulus.data = tcnf->modulus.data;
  out->tc.generator.len = tcnf->generator.len;
  out->tc.generator.data = tcnf->generator.data;
}

static struct t_pwent *tpent_parse(char *str, int len)
{
    static struct t_pw tbuf;
    char *cp;

    tbuf.pebuf.name = tbuf.userbuf;
    tbuf.pebuf.password.data = tbuf.pwbuf;
    tbuf.pebuf.salt.data = tbuf.saltbuf;
    
    cp   = _yp_xstrtok(str, ':');
    if (cp == NULL)
	return NULL;
    strncpy(tbuf.pebuf.name, cp, sizeof(tbuf.userbuf));
    
    cp = _yp_xstrtok(NULL, ':');
    if (cp == NULL)
	return NULL;
    tbuf.pebuf.password.len = t_fromb64(tbuf.pebuf.password.data, cp);
    if(tbuf.pebuf.password.len <= 0)
        return NULL;

    cp = _yp_xstrtok(NULL, ':');
    if (cp == NULL)
        return NULL;
    tbuf.pebuf.salt.len = t_fromb64(tbuf.pebuf.salt.data, cp);
    if(tbuf.pebuf.salt.len <= 0)
        return NULL;
    
    cp = _yp_xstrtok(NULL, ':');
    if (cp == NULL || !isdigit(*cp))
	return NULL;
    tbuf.pebuf.index    = atoi(cp);

    return &tbuf.pebuf;
}


void _yp_settpent(void)
{
    rewind_flag = 1;
    if (savekey)
	free(savekey);
}


void _yp_endtpent(void)
{
    rewind_flag = 1;
    if (savekey)
	free(savekey);
}


struct t_pwent *_yp_gettpent(void)
{
    struct t_pwent *pw;
    struct t_confent *tc;
    char *map;
    char *domain;
    char *result;
    int len;
    char *outkey;
    int keylen;


    map = _ypopts_getmd("tpasswd", ".byname", &domain);
    if (map == NULL)
	return NULL;

    pw = NULL;
    
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
    while (((pw = tpent_parse(result, len)) == NULL ||
	    (tc = _yp_gettcid(pw->index)) == NULL) && errno == 0)
    {
#ifdef DEBUG
	fprintf(stderr, "yp_tpasswd: Invalid passwd entry: %.*s\n",
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

    free(map);
    free(domain);

    pwsetup(&tpass, pw, tc);
    return &tpass;

  error:
    free(map);
    free(domain);
    return NULL;
}


struct t_passwd *_yp_gettpnam(const char *name)
{
    struct t_pwent *pw;
    struct t_confent * tc;
    char *map;
    char *domain;
    char *result;
    int len;

    map = _ypopts_getmd("tpasswd", ".byname", &domain);
    if (map == NULL)
	return NULL;

    pw = NULL;
    if (yp_match(domain, map, name, strlen(name), &result, &len) == 0)
    {
	pw = tpent_parse(result, len);
	if(pw != NULL && (tc = _yp_gettcid(pw->index)) == NULL)
	  pw = NULL;
	free(result);
    }

    free(map);
    free(domain);
    if(pw == NULL)
      return NULL;
    pwsetup(&tpass, pw, tc);
    return &tpass;
}

#endif /* ENABLE_YP */
