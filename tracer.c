#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "libelf.h"

void emitreg(FILE * fd, pid_t child, const char * name, unsigned long long int val, unsigned long long int *lastval);

void emitreg(FILE * fd,pid_t child, const char * name, unsigned long long int val, unsigned long long int *lastval) {
  long ins;
  if ( *lastval != val ){
    fprintf(fd, "'%s':'0x%lx', ",name, val);
    ins = ptrace(PTRACE_PEEKTEXT, child, val, NULL);
    fprintf(fd, "'%s.val':'0x%lx', ",name, ins);
  }
  *lastval = val; // save it

}

#define EMITREG(X) emitreg(fd,child, "" # X, regs. X, & lastreg . X);
#define INITREG(X) lastreg. X = 0;



int main(int argc, char *argv[]){
  FILE * fd = stdout;
  int status, begin, end, c;
  pid_t child;
  struct user_regs_struct regs;
  struct user_regs_struct lastreg;

  INITREG(r15);
  INITREG(r14);
  INITREG(r13);
  INITREG(r12);
  INITREG(rbp);
  INITREG(rbx);
  INITREG(r11);
  INITREG(r10);
  INITREG(r9);
  INITREG(r8);
  INITREG(rax);
  INITREG(rcx);
  INITREG(rdx);
  INITREG(rsi);
  INITREG(rdi);
  INITREG(orig_rax);
  INITREG(rip);
  INITREG(cs);
  INITREG(eflags);
  INITREG(rsp);
  INITREG(ss);
  INITREG(fs_base);
  INITREG(gs_base);
  INITREG(ds);
  INITREG(es);
  INITREG(fs);
  INITREG(gs);


  /* parse command line options */
  //  while ((c = getopt(argc, argv, "ho:")) != -1)
  //switch(c)
  //  {
  //  case 'h':
  //    fprintf(stderr,
  //            "Usage: tracer [-o FILE] PROGRAM [ARG...]\n"
  //            "Run PROGRAM on ARGs printing each value of the program\n"
  //            "counter to FILE or to STDOUT if FILE is not specified.\n");
  //    return 1;
  //  case 'o':
  fd = fopen(argv[2], "w");
  //      break;
  //default:
  ///abort();
  //}
  optind = 3;
  /* ensure the file exists */
  if(access(argv[optind], F_OK) == -1){
    fprintf(stderr,"program file `%s' does not exist.\n", argv[optind]);
    return 1;
  }

  /* get on with it */
  begin = get_text_address(argv[optind]);
  end   = begin + get_text_offset(argv[optind]);
  switch (child=fork()){
  case -1: // error
    printf("fork error\n");
    return 1;
    break;
  case 0:  // child
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    // don't let child print to STDOUT if we're writing to STDOUT
    if (fd == stdout)
      freopen("/dev/null", "a", stdout);
    execvp(argv[optind], &argv[optind]);
    break;
  default: // parent
    while(1) {
      wait(&status);
      if(WIFEXITED(status)) break;
      ptrace(PTRACE_GETREGS, child, NULL, &regs);

      // load the instruction
      fprintf(fd, "{ 'pid' : '%d', ", child);
      
      EMITREG(r15);
      EMITREG(r14);
      EMITREG(r13);
      EMITREG(r12);
      EMITREG(rbp);
      EMITREG(rbx);
      EMITREG(r11);
      EMITREG(r10);
      EMITREG(r9);
      EMITREG(r8);
      EMITREG(rax);
      EMITREG(rcx);
      EMITREG(rdx);
      EMITREG(rsi);
      EMITREG(rdi);
      EMITREG(orig_rax);
      EMITREG(rip);
      EMITREG(cs);
      EMITREG(eflags);
      EMITREG(rsp);
      EMITREG(ss);
      EMITREG(fs_base);
      EMITREG(gs_base);
      EMITREG(ds);
      EMITREG(es);
      EMITREG(fs);
      EMITREG(gs);
  

      // print if in or out
      fprintf(fd, ", 'inside : '%s' }\n",((begin <= regs.PC_REG) && (end >= regs.PC_REG)) ? "IN": "OUT" );

      
      ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
    }
    return status;
    break;
  }
}
