protego
=======

Protego is a linux variant based on Ubuntu that never raises 
the privilege of an user that isn't the administrator. 
Specifically, Protego removes the need for utilities that are 
setuid-to-root. Protego currently de-privileges 12,732 lines 
of code in trusted setuid-to-root binaries by changing just 
715 lines of kernel code.


We have carefully studied 28 setuid-to-root binaries. According 
to the Debian and Ubunty "popularity contest" results, this set 
includes all binaries installed on more than 10.5% of systems surveyed.

There are an additional 91 binaries packaged and distributed by Ubuntu, 
and testing that these work on Protego is ongoing work. Based on 
documentation, most of these use interfaces Protego has already 
addressed, but check back later for updates.

Note: Please refer to setup.sh for instructions to setup protego.
