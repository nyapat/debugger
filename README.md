1. Navigate to build/
2. Run `make`
3. Compile the test program `g++ ../hello/main.cpp -g -gdwarf-4 -o ../hello/hello.o`
4. Run `./myapp ../hello/hello.o`
5. Debug it `b 0x1161` `c` `registers dump`

Todo:

- [ ] figure out how to not use dwarf4
- [ ] fix the weird error on starting up the program
- [ ] inline and member functions
