/*
** nsswitch.c              Name Service Switch support functions
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

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "nsswitch.h"

static FILE *nswfp = NULL;

char *_nsw_opts = NULL;


int setnswent(void)
{
    extern char *getenv();

    if (nswfp)
	fclose(nswfp);

#ifdef DEBUG
    if (getenv("NSWCONF"))
	nswfp = fopen(getenv("NSWCONF"), "r");
    else
#endif

    nswfp = fopen(PATH_NSWCONF, "r");
    
    return (nswfp == NULL ? -1 : 0);
}


void endnswent(void)
{
    if (nswfp)
    {
	fclose(nswfp);
	nswfp = NULL;
    }
}


struct nsw *getnswent(void)
{
    static struct nsw nswb;
    static char buf[1024];
    char *cp, *tmp;
    
    if (!nswfp)
	setnswent();


    if (nswfp == NULL)
	return NULL;
    
    do
    {
	cp = fgets(buf, sizeof(buf), nswfp);
	if (cp == NULL)
	    return NULL;
	
	tmp = strchr(cp, '#');
	if (tmp)
	    *tmp = '\0';
	
	while (isspace(*cp))
	    cp++;
    } while (*cp == '\0');
    
    tmp = cp;
    
    cp = strchr(cp, ':');
    if (!cp)
	return NULL;
    
    *cp++ = '\0';
    strncpy(nswb.name,tmp,sizeof(nswb.name)-1);
    
    while (isspace(*cp))
	cp++;
    
    for (nswb.orderc = 0; *cp; nswb.orderc++)
    {
	tmp = cp;
	
	do
	{
	    cp++;
	} while (!isspace(*cp) && *cp != '\0');
	
	if (*cp)
	    *cp++ = '\0';
	
	if (strcmp(tmp, "[NOTFOUND=return]") == 0)
	    nswb.orderl[nswb.orderc] = NSWO_RETURN;
	else if (strcmp(tmp, "files") == 0)
	    nswb.orderl[nswb.orderc] = NSWO_FILES;
#ifdef ENABLE_YP	
	else if (strcmp(tmp, "nis") == 0 || strcmp(tmp, "yp") == 0)
	    nswb.orderl[nswb.orderc] = NSWO_NIS;
#endif
#ifdef ENABLE_NIS
	else if (strcmp(tmp, "nisplus") == 0 || strcmp(tmp, "nis+") == 0)
	    nswb.orderl[nswb.orderc] = NSWO_NISPLUS;
#endif
#ifdef ENABLE_DNS
	else if (strcmp(tmp, "dns") == 0)
	    nswb.orderl[nswb.orderc] = NSWO_DNS;
#endif
#ifdef ENABLE_DBM
	else if (strcmp(tmp, "dbm") == 0)
	    nswb.orderl[nswb.orderc] = NSWO_DBM;
#endif
	else
	    return NULL;
	
	while (isspace(*cp))
	    cp++;
    }
    
    return &nswb;
}


static int nswcache_cnt  = 0;
static int nswcache_size = 0;
static struct nsw *nswcache = NULL;


static int nsw_loadcache(void)
{
    struct nsw *nswp;


    setnswent();

    if (!nswcache)
    {
	nswcache_size = 64;
	nswcache = (struct nsw *) calloc(nswcache_size, sizeof(struct nsw));
	if (!nswcache)
	{
	    endnswent();
	    return -1;
	}
    }

    for (nswcache_cnt = 0;
	 (nswp = getnswent()) != NULL;
	 nswcache_cnt++)
    {
	if (nswcache_cnt >= nswcache_size)
	{
	    nswcache_size += 64;
   
	    nswcache = (struct nsw *) realloc(nswcache,
					     nswcache_size*sizeof(struct nsw));
	    if (!nswcache)
	    {
		endnswent();
		return -1;
	    }
	}

	nswcache[nswcache_cnt] = *nswp;
    }

    endnswent();
    return 0;
}



struct nsw *getnswbyname(char *name)
{
    int i;

    
    if (nswcache == NULL)
	nsw_loadcache();

    /* First try to locate it in the cache */
    for (i = 0; i < nswcache_cnt && strcmp(name, nswcache[i].name); i++)
	;

    if (i < nswcache_cnt)
	return &nswcache[i];

    /* Force a reload of the cache */
    nsw_loadcache();

    /* And check the cache again! */
    for (i = 0; i < nswcache_cnt && (strcmp(name, nswcache[i].name),1); i++)
	;

    if (i < nswcache_cnt)
	return &nswcache[i];

    return NULL;
}
