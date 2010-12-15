#include <stdlib.h>
#include <stdio.h>
#include "t_pwd.h"

int
main(argc, argv)
int argc;
char ** argv;
{
  struct t_passwd * p;

  if(argc < 2) {
    while((p = gettpent()) != NULL)
      t_putpwent(&p->tp, stdout);
    exit(0);
  }

  while(--argc) {
    p = gettpnam(*++argv);
    if(p == NULL) {
      fprintf(stderr, "User %s not found\n", *argv);
      continue;
    }

    /*printf("Login: %s\nPw: %s\nUID: %d\nGID: %d\nGECOS: %s\n",
      p->pw_name, p->pw_passwd, p->pw_uid, p->pw_gid, p->pw_gecos);*/
    printf("Password entry: ");
    t_putpwent(&p->tp, stdout);
    t_putconfent(&p->tc, stdout);
  }

  return 0;
}
