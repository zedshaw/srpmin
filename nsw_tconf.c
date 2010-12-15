/*
** nsw_tconf.c - derived from...
** nsw_passwd.c           Passwd cover routines for the Name Service Switch
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
*/

#include "config.h"
#include "nys_config.h"

#ifdef ENABLE_NSW

#include <stdio.h>
#include <errno.h>
#include "nsswitch.h"
#include "t_pwd.h"
#include "nss_defs.h"

static struct nsw *nswp = NULL;
static int setptr  = 0;
static int setflag = 0;


#define RETOBJTYPE struct t_confent *
#define NSWENTRY   "tconf"
#define FUNCOBJENT tcent


#include "setXXent.h"
#include "endXXent.h"
#include "getXXent.h"


#define FUNCNAME gettcid
#define REQOBJTYPE int
#include "getXXbyYY.h"
#undef FUNCNAME
#undef REQOBJTYPE

#endif
