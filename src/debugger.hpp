#ifndef DEBUGGER_HPP
#define DEBUGGER_HPP

#include "breakpoint.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <sys/siginfo.h>
#include <unordered_map>

class Debugger {
public:
  Debugger(std::string prog_name, pid_t pid)
      : m_prog_name{std::move(prog_name)}, m_pid{pid} {
    auto fd = open(m_prog_name.c_str(), O_RDONLY);

    m_elf = elf::elf(elf::create_mmap_loader(fd));
    m_dwarf = dwarf::dwarf(dwarf::elf::create_loader(m_elf));
  }

  void run();
  void handle_command(const std::string &line);
  void continue_execution();
  void set_breakpoint_at_addr(std::intptr_t addr);
  void dump_registers();
  auto read_memory(uint64_t addr) -> uint64_t;
  void write_memory(uint64_t addr, uint64_t val);
  auto get_pc() -> uint64_t;
  void set_pc(uint64_t pc);
  void step_over_bp();
  void wait_for_signal();
  auto get_base_addr() -> uint64_t;
  auto get_function_from_pc(uint64_t pc) -> dwarf::die;
  auto get_line_entry_from_pc(uint64_t pc) -> dwarf::line_table::iterator;
  auto offset_load_address(uint64_t addr) -> uint64_t;
  void print_source(const std::string &file, unsigned line,
                    unsigned n_lines_context = 2);
  auto get_signal_info() -> siginfo_t;
  void handle_sigtrap(siginfo_t info);
  void print_current_line();

private:
  std::string m_prog_name;
  pid_t m_pid;
  std::unordered_map<std::intptr_t, Breakpoint> m_breakpoints;
  std::optional<uint64_t> base_address;

  dwarf::dwarf m_dwarf;
  elf::elf m_elf;
};

#endif
