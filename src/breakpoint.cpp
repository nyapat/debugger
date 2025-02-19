#include "breakpoint.hpp"
#include <cstdio>
#include <cstdlib>
#include <sys/ptrace.h>

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
