# ROPInjector

A tool written in C (Win32) to convert any shellcode in ROP and patch it into a given portable executable (PE). It supports only 32-bit target PEs and the x86 instruction set.

Published in Blackhat USA 2015, "ROPInjector: Using Return Oriented Programming for Polymorphism and Antivirus Evasion"
More info: 
 - (white paper) https://www.blackhat.com/docs/us-15/materials/us-15-Xenakis-ROPInjector-Using-Return-Oriented-Programming-For-Polymorphism-And-Antivirus-Evasion-wp.pdf
 - (presentation) https://www.blackhat.com/docs/us-15/materials/us-15-Xenakis-ROPInjector-Using-Return-Oriented-Programming-For-Polymorphism-And-Antivirus-Evasion.pdf

## Usage
```
  ropinjector \<file-to-infect\> \<shellcode-file\> \<output-file\>* [options]*
```

(\* denotes optional arguments)

* file-to-infect	: any 32-bit, non-packed PE

* shellcode-file	: the shellcode to patch in the PE file

* output-file		(optional) : The name of the output file. If not specified, 
				ROPInjector will choose a suitable filename indicating the 
				type of injection performed.

* options : 

```
				
	text		Force reading of shellcode file as text file. Shellcode in text 
				form must be in the \xHH\xHH\xHH format.
	
	norop		Don't transform shellcode to ROP.
	
	nounroll	Don't unroll SIBs.
	
	noinj		Don't inject missing gadgets.
	
	getpc		Don't replace getPC constructs in the shellcode.
	
	entry		Have shellcode run before the original PE code. Without this
				option, ROPInjector will try to hook calls to ExitProcess(),
				exit() and the like so that the shellcode runs last, right
				before process exit.
				
	-d<secs>	Number of seconds to Sleep() before executing the shellcode.
				When this option is specified, "entry" is also implicitly used.

```

ROPInjector will output some comma-delimited stats in the end. These are (in order of appearance):
- the carrier PE filename 
- the output filename of the resulting patched file
- initial size of the PE file in bytes
- shellcode size in bytes
- patch size in bytes
- whether unroll is performed
- whether shellcode has been converted to ROP
- whether getPC constructs are replaced in the shellcode
- whether access is given to the shellcode during entry (run first) or during exit (run last)
- the delay the shellcode sleeps before it runs in seconds
- initial number of instructions in the shellcode
- number of instructions in the shellcode after unrolling and other manipulations, but before ROP
- number of instructions replaced by ROP gadgets (out of the ones in the previous metric, and not the initial number of instructions)
- number of gadgets injected
- number of gadget segments
- number of instructions replaced by injected gadgets

## LICENSE
GPLv2.0, http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
