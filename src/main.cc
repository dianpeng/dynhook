#include "dynhook.h"

int main(int argc, char* argv[]) {
  return dynhook::run_main(argc,argv) ? 0 : -1;
}
