Important notes:

-All my code is located within sim.c

-The maximum number of symbols that can be stored is currently set to 500. I chose this as a reasonable number given the size of the obj files we have written and used so far.

-I have placed several debug print statements throughout my code that have been commented out. These can be uncommented if a strange error occurs.

-For some reason, my errno checking is NOT working on eniac although it works fine on my laptop. As a result, set may default to setting the PC or register to x0000 if the value or label is invalid.

set command
-----------

I have allowed users to enter in addresses past xFFFF without throwing an error. My code just casts the value to an unsigned short and uses that to set the register value.

Users can also use the hex format 0x instead of just x to specify hex values.


break set/clear command
-----------------------

I decided to allow the user to select as many breakpoints as he/she wants.
