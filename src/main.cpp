#include <algorithm>
#include <array>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <execinfo.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <libelfin/dwarf/dwarf++.hh>
#include <libelfin/elf/elf++.hh>
#include <linenoise.h>
#include <optional>
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

class Breakpoint {
public:
  Breakpoint() = default;
  Breakpoint(pid_t pid, std::intptr_t addr)
      : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{} {}

  void enable();
  void disable();

  auto is_enabled() const -> bool { return m_enabled; }
  auto get_address() const -> std::intptr_t { return m_addr; }

private:
  pid_t m_pid;
  std::intptr_t m_addr;
  bool m_enabled;
  uint8_t m_saved_data;
};

auto Breakpoint::enable() -> void {
  auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
  m_saved_data = static_cast<uint8_t>(data & 0xff);
  uint64_t int3 = 0xcc;
  uint64_t data_bp = ((data & ~0xff) | int3);
  if (ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_bp) == -1) {
    perror("ptrace POKEDATA failed");
    exit(1);
  }

  m_enabled = true;
}

auto Breakpoint::disable() -> void {
  auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
  auto saved = ((data & ~0xff) | m_saved_data);
  ptrace(PTRACE_POKEDATA, m_pid, m_addr, saved);

  m_enabled = false;
}

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
