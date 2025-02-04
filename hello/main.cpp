#include <csignal>
#include <iostream>

int main() {
  std::cerr << "Hello I am a program in the year 2025\n";
  std::cerr << "This is another line\n";
  raise(SIGSEGV);
  return 0;
}
