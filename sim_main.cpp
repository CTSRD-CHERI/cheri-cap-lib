#include "Vmodule_wrap128_fromMem.h"
#include "verilated.h"
#include "verilated_vpi.h"  // Required to get definitions

vluint64_t main_time = 0;   // See comments in first example
double sc_time_stamp() { return main_time; }

template <class T, size_t N> constexpr size_t array_size(T (&)[N]) { return N; }

int main(int argc, char** argv, char** env) {
  Verilated::commandArgs(argc, argv);
  Vmodule_wrap128_fromMem* top = new Vmodule_wrap128_fromMem;
  Verilated::internalsDump();  // See scopes to help debug
  for (int i = 0; i < array_size(top->wrap128_fromMem_mem_cap); i++) {
    top->wrap128_fromMem_mem_cap[i] = 0;
    printf("Input[%d]=%d\n", i, top->wrap128_fromMem_mem_cap[i]);
  }
  printf("Eval:\n");
  // while (!Verilated::gotFinish()) {
  top->eval();
  //}
  for (int i = 0; i < array_size(top->wrap128_fromMem); i++) {
    printf("Output[%d]=%d\n", i, top->wrap128_fromMem[i]);
  }
  delete top;
  exit(0);
}
