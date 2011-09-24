About srpmin
============

This is a copy of the original [libsrp](http://srp.stanford.edu/) written
by Tom Wu (creator of SRP) but with all the extraneous things you don't need
like NIS and PAM integration.  It does not alter the code to his library
except for fixing a few minor bugs in output formatting of hex codes
and creating a "srp_simple.c" file that simplifies using the 
SRP6a protocol.

It also doesn't have all of the previous versions of SRP since those
are known to be vulnerable.


Building
========

Just the usual ./configure && make && make install 

It will put a libsrp.a file in /usr/local/lib for you to use.


Using
=====

Take a look at srp6bench for how to use the base API.

Look at srp_simple.c for a simplification layer that does most of what you
probably want to do using only HEX encoded strings for everything.
This library is for easier use with scripting languages that can't handle
complex binary blob types or C structs.  It also helps to get the
encodings right since it's only giving you properly HEX encoded
values.

Base64 wasn't used because after *numerous* attempts to use it with
various languages I found that Base64 is too variable, and that 
HEX encoded strings were the most reliable and easiest to debug.

Finally, look in simple_test.c for an example of using the srp_simple.c
layer.


Mac OSX Lion
============

For whatever idiotic reason Apple decided to deprecate all of
OpenSSL.  You'll get deprecation warnings, and you should just
ignore them until there's a better explanation as to why and
a proper workaround that doesn't involve rewriting everything
to use Apple's libraries.


