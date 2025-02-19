1. Navigate to build/
2. Run `make`
3. Compile the test program `g++ ../hello/main.cpp -g -gdwarf-4 -o ../hello/hello.o`
4. Run `./myapp ../hello/hello.o`
5. Debug it `b 0x1161` `c` `registers dump`

todo:

- [ ] figure out how to not use dwarf4 (this library i'm using is causing a bunch of errors)
- [ ] fix the weird error on starting up the program
- [ ] inline and member functions
