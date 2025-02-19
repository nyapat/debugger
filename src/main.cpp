#include "debugger.hpp"
#include <algorithm>
#include <array>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <execinfo.h>
#include <fcntl.h>
#include <iostream>
#include <libelfin/dwarf/dwarf++.hh>
#include <libelfin/elf/elf++.hh>
#include <linenoise.h>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

auto split(const std::string &s, char delimiter) -> std::vector<std::string> {
  std::vector<std::string> out{};
  std::stringstream ss{s};
  std::string item;

  while (std::getline(ss, item, delimiter)) {
    out.push_back(item);
  }

  return out;
}

auto is_prefix(const std::string &s, const std::string &of) -> bool {
  if (s.size() > of.size())
    return false;
  return std::equal(s.begin(), s.end(), of.begin());
}

enum class reg {
  rax,
  rbx,
  rcx,
  rdx,
  rdi,
  rsi,
  rbp,
  rsp,
  r8,
  r9,
  r10,
  r11,
  r12,
  r13,
  r14,
  r15,
  rip,
  rflags,
  cs,
  orig_rax,
  fs_base,
  gs_base,
  fs,
  gs,
  ss,
  ds,
  es
};

constexpr std::size_t n_registers = 27;

struct reg_descriptor {
  reg r;
  int dwarf_r;
  std::string name;
};

static const std::array<reg_descriptor, n_registers> g_register_descriptors{{
    {reg::r15, 15, "r15"},
    {reg::r14, 14, "r14"},
    {reg::r13, 13, "r13"},
    {reg::r12, 12, "r12"},
    {reg::rbp, 6, "rbp"},
    {reg::rbx, 3, "rbx"},
    {reg::r11, 11, "r11"},
    {reg::r10, 10, "r10"},
    {reg::r9, 9, "r9"},
    {reg::r8, 8, "r8"},
    {reg::rax, 0, "rax"},
    {reg::rcx, 2, "rcx"},
    {reg::rdx, 1, "rdx"},
    {reg::rsi, 4, "rsi"},
    {reg::rdi, 5, "rdi"},
    {reg::orig_rax, -1, "orig_rax"},
    {reg::rip, -1, "rip"},
    {reg::cs, 51, "cs"},
    {reg::rflags, 49, "eflags"},
    {reg::rsp, 7, "rsp"},
    {reg::ss, 52, "ss"},
    {reg::fs_base, 58, "fs_base"},
    {reg::gs_base, 59, "gs_base"},
    {reg::ds, 53, "ds"},
    {reg::es, 50, "es"},
    {reg::fs, 54, "fs"},
    {reg::gs, 55, "gs"},
}};

auto get_register_value(pid_t pid, reg r) -> uint64_t {
  user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

  auto it =
      std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                   [r](auto &&rd) { return rd.r == r; });

  return *(reinterpret_cast<uint64_t *>(&regs) +
           (it - begin(g_register_descriptors)));
}

auto set_register_value(pid_t pid, reg r, uint64_t value) {
  user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

  auto it =
      std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                   [r](auto &&rd) { return rd.r == r; });

  *(reinterpret_cast<uint64_t *>(&regs) +
    (it - begin(g_register_descriptors))) = value;

  ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}

auto get_register_value_from_dwarf_register(pid_t pid, unsigned regnum)
    -> uint64_t {
  auto it =
      std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                   [regnum](auto &&rd) { return rd.dwarf_r == regnum; });

  if (it == end(g_register_descriptors)) {
    throw std::out_of_range("Unknown dwarf register");
  }

  return get_register_value(pid, it->r);
}

auto get_register_name(reg r) -> std::string {
  auto it =
      std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                   [r](auto &&rd) { return rd.r == r; });

  return it->name;
}

auto get_register_from_name(const std::string &name) -> reg {
  auto it =
      std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                   [name](auto &&rd) { return rd.name == name; });

  return it->r;
}

auto execute_debugee(const std::string &prog_name) -> void {
  if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
    std::cerr << "Error ptracing debugee";
    return;
  }

  execl(prog_name.c_str(), prog_name.c_str(), nullptr);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "No program name";
    return -1;
  }

  auto prog = argv[1];
  pid_t pid = fork();

  if (pid == 0) {
    // child
    personality(ADDR_NO_RANDOMIZE);
    execute_debugee(prog);
  } else if (pid >= 1) {
    // parent
    std::cout << "Debugging process " << pid << std::endl;
    Debugger dbg{prog, pid};
    dbg.run();
  }
}
