#include "debugger.hpp"
#include "breakpoint.hpp"

#include <csignal>
#include <execinfo.h>
#include <fstream>
#include <iostream>
#include <ostream>
#include <sys/ptrace.h>
#include <sys/siginfo.h>
#include <sys/wait.h>

auto Debugger::print_current_line() -> void {
  void *array[10];
  size_t size;
  size = backtrace(array, 10);

  for (size_t i = 0; i < size; ++i) {
    uintptr_t pc = reinterpret_cast<uintptr_t>(array[i]);
    auto offset = offset_load_address(pc);
    try {
      auto line_entry = get_line_entry_from_pc(offset);
      print_source(line_entry->file->path, line_entry->line, 0);
      return;
    } catch (...) {
      std::cout << "Can't find line entry :( " << pc << " " << offset
                << std::endl;
    }
  }
}

auto Debugger::handle_sigtrap(siginfo_t info) -> void {
  switch (info.si_code) {
  case SI_KERNEL:
  case TRAP_BRKPT: {
    set_pc(get_pc() - 1);
    std::cout << "Breakpoint at 0x" << std::hex << get_pc() << std::endl;
    auto offset = offset_load_address(get_pc());
    auto line_entry = get_line_entry_from_pc(offset);
    print_source(line_entry->file->path, line_entry->line);
    return;
  }
  case TRAP_TRACE:
    return;
  default:
    std::cout << "Unknown SIGTRAP " << info.si_code << std::endl;
    return;
  }
}

auto Debugger::get_signal_info() -> siginfo_t {
  siginfo_t info;
  ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
  return info;
}

auto Debugger::print_source(const std::string &file_name, unsigned line,
                            unsigned n_lines_context) -> void {
  std::ifstream file{file_name};

  auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
  auto end_line = line + n_lines_context +
                  (line < n_lines_context ? n_lines_context - line : 0) + 1;

  char c{};
  auto current = 1u;

  while (current != start_line && file.get(c)) {
    if (c == '\n')
      ++current;
  }

  std::cout << (current == line ? "> " : "  ");

  while (line <= end_line && file.get(c)) {
    std::cout << c;
    if (c == '\n') {
      ++current;
      std::cout << (current == line ? "> " : "  ");
    }
  }

  std::cout << std::endl;
}

auto Debugger::offset_load_address(uint64_t addr) -> uint64_t {
  return addr - *base_address;
}

auto Debugger::get_line_entry_from_pc(uint64_t pc)
    -> dwarf::line_table::iterator {
  for (auto &cu : m_dwarf.compilation_units()) {
    if (die_pc_range(cu.root()).contains(pc)) {
      auto &lt = cu.get_line_table();
      auto it = lt.find_address(pc);
      if (it == lt.end()) {
        throw std::out_of_range("Cannot find line entry");
      } else {
        return it;
      }
    }
  }

  throw std::out_of_range("Cannot find line entry");
}

auto Debugger::get_function_from_pc(uint64_t pc) -> dwarf::die {
  for (auto &cu : m_dwarf.compilation_units()) {
    if (dwarf::die_pc_range(cu.root()).contains(pc)) {
      for (const auto &die : cu.root()) {
        if (die.tag == dwarf::DW_TAG::subprogram) {
          if (die_pc_range(die).contains(pc))
            return die;
        }
      }
    }
  }

  // Todo: member funcs, inlining

  throw std::out_of_range("Cannot find function");
}

auto Debugger::get_base_addr() -> uint64_t {
  if (base_address.has_value())
    return base_address.value();

  // read from /proc/pid/maps first line
  const std::string path = "/proc/" + std::to_string(m_pid) + "/maps";
  std::ifstream maps_file(path);
  std::string line;
  std::getline(maps_file, line, '-');

  try {
    base_address = std::stoull(line, 0, 16);
    // base_address = std::stoull(line.substr(0, addr_end), nullptr, 16);
  } catch (...) {
    std::cerr << "Failed when parsing base address\n";
    return -1;
  }

  return *base_address;
}

auto Debugger::wait_for_signal() -> void {
  int wait_status;
  auto options = 0;

  waitpid(m_pid, &wait_status, options);

  auto siginfo = get_signal_info();

  switch (siginfo.si_signo) {
  case SIGTRAP:
    handle_sigtrap(siginfo);
    break;
  case SIGSEGV:
    // get line here
    print_current_line();
    std::cout << "Segfaulted " << siginfo.si_code << std::endl;
    break;
  default:
    std::cout << "Signal " << strsignal(siginfo.si_signo) << std::endl;
  }
}

auto Debugger::get_pc() -> uint64_t {
  return get_register_value(m_pid, reg::rip);
}

auto Debugger::set_pc(uint64_t pc) -> void {
  set_register_value(m_pid, reg::rip, pc);
}

auto Debugger::step_over_bp() -> void {
  if (m_breakpoints.count(get_pc())) {
    auto &bp = m_breakpoints[get_pc()];

    if (bp.is_enabled()) {
      bp.disable();
      ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
      wait_for_signal();
      bp.enable();
    }
  }
}

auto Debugger::read_memory(uint64_t addr) -> uint64_t {
  return ptrace(PTRACE_PEEKDATA, m_pid, addr, nullptr);
}

auto Debugger::write_memory(uint64_t addr, uint64_t val) -> void {
  ptrace(PTRACE_POKEDATA, m_pid, addr, val);
}

auto Debugger::dump_registers() -> void {
  for (const auto &rd : g_register_descriptors) {
    std::cout << rd.name << " 0x" << std::setfill('0') << std::setw(16)
              << std::hex << get_register_value(m_pid, rd.r) << std::endl;
  }
}

auto Debugger::set_breakpoint_at_addr(std::intptr_t addr) -> void {
  intptr_t target = static_cast<intptr_t>(*base_address) + addr;
  std::cout << "Set breakpoint at 0x" << std::hex << target << std::endl;
  Breakpoint bp{m_pid, static_cast<intptr_t>(target)};
  bp.enable();
  m_breakpoints[target] = bp;
}

auto Debugger::continue_execution() -> void {
  step_over_bp();
  ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
  wait_for_signal();
}

auto Debugger::handle_command(const std::string &line) -> void {
  auto args = split(line, ' ');
  auto command = args[0];

  if (is_prefix(command, "continue")) {
    continue_execution();
  } else if (is_prefix(command, "break")) {
    std::string addr{args[1], 2};
    set_breakpoint_at_addr(std::stol(addr, 0, 16));

    auto check =
        ptrace(PTRACE_PEEKDATA, m_pid, std::stol(addr, 0, 16), nullptr);
  } else if (is_prefix(command, "register")) {
    if (is_prefix(args[1], "dump")) {
      dump_registers();
    } else if (is_prefix(args[1], "read")) {
      std::cout << get_register_value(m_pid, get_register_from_name(args[2]))
                << std::endl;
    } else if (is_prefix(args[1], "write")) {
      std::string val{args[3], 2};
      set_register_value(m_pid, get_register_from_name(args[2]),
                         std::stol(val, 0, 16));
    }
  } else if (is_prefix(command, "memory")) {
    std::string addr{args[2], 2};

    if (is_prefix(args[1], "read")) {
      std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
    } else if (is_prefix(args[1], "write")) {
      std::string val{args[3], 2};
      write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
    }
  } else {
    std::cerr << "Unknown command\n";
  }
}

auto Debugger::run() -> void {
  wait_for_signal();
  if (!base_address.has_value()) {
    get_base_addr();
  }

  char *line = nullptr;
  while ((line = linenoise("dbg> ")) != nullptr) {
    handle_command(line);
    linenoiseHistoryAdd(line);
    linenoiseFree(line);
  }
}
