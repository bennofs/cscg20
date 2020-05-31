## Instructions for Squirrel as a Service

1. Clone the repo @ `https://github.com/albertodemichelis/squirrel.git`
2. Build the original squirrel code with `cmake`. `mkdir build; cd build; cmake ..; make`
3. Create a local copy of the built `sq` in  `bin/sq`: `cp bin/sq bin/sq_orig`
4. Replace the `sq/sq.c` file with the provided one
5. Optional: Adjust the makefiles to your needs (Debugging flags might be a good idea)
6. Build a new 64 bit binary with `make `

You can use the `sq_orig` afterwards to compile scripts to the binary format, e.g. with: `./sq_orig -o compiled.cnut -c test.nut`. 

For any questions ping 0x4d5a @ Discord. Good luck