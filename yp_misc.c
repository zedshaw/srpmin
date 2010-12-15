/*
** yp_misc.c           NIS Version 2 miscellaneous support functions
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
** Authors: Peter Eriksson <pen@signum.se>
**          Michael A. Griffith <grif@cs.ucr.edu>
*/

#include "config.h"
#include "nys_config.h"

#ifdef ENABLE_YP


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpcsvc/ypclnt.h>
#include "yp_misc.h"


char *_yp_strip_names(char *buff)
{
   /*
    * There has to be a way to do this in idiomatic `C'.  MAG
    */

   int i;
   
   while (isspace(*buff) && (*buff != '\0'))
      ++buff;
   
   i = strlen(buff);
   
   while ((i > 0) && (isspace(buff[i])))
   {
      buff[i] = '\0';
      --i;
   }

   return buff;
}


char *_yp_xcopy(char **cp, char *str)
{
    char *start = *cp;
    
    if (str != NULL)
	while (*str)
	    *(*cp)++ = *str++;

    *(*cp)++ = '\0';
    return start;
}


char *_yp_xstrtok(char *cp, int delim)
{
    static char *str = NULL;

    if (cp)
	str = cp;

    if (*str == '\0')
	return NULL;

    cp = str;

    /*
     * Treatment of white space as a special case is NOT compatible
     * with strtok() from the standard C library.  However, it does
     * simplify parsing of the YP maps.  MAG.
     */

    if (delim == ' ')
       while (*str && (!isspace(*str)))
	  str++;
    else
       while (*str && *str != delim)
	  str++;

    if (*str)
	*str++ = '\0';

    return cp;
}

static char *defdomain = NULL;

char *_ypopts_getmd(char *defmap, char *suffix, char **domain)
{
    char *map;
    void *optsp = NULL;
    
    
    if (optsp == NULL)
    {
        if (defdomain == NULL) {
	  if (yp_get_default_domain(&defdomain))
	    return NULL;
	}
	*domain = (char *) malloc(strlen(defdomain)+1);
	if (*domain == NULL)
	  return NULL;
	strcpy(*domain, defdomain);

	map = (char *) malloc(strlen(defmap)+strlen(suffix)+1);
	if (map == NULL)
	{
	    free(*domain);
	    return NULL;
	}
	
	strcpy(map, defmap);
	strcat(map, suffix);

	return map;
    }
    else
    {
	/* Deal with opts. Later... */

	return NULL;
    }
}

#endif /* ENABLE_YP */
