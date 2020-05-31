#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#include <memory>

#include <squirrel.h>
#include <squirrel/sqpcheader.h>
#include <squirrel/sqstring.h>
#include <squirrel/sqvm.h>
#include <squirrel/sqfuncproto.h>
#include <squirrel/sqstate.h>
#include <squirrel/sqtable.h>
#include <squirrel/sqclosure.h>
#include <sqstdblob.h>
#include <sqstdsystem.h>
#include <sqstdio.h>
#include <sqstdmath.h>
#include <sqstdstring.h>
#include <sqstdaux.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#define phase(fmt, ...) fprintf(stderr, "\e[43m🚀\e[0m " fmt "\n", ##__VA_ARGS__);
#define debug(fmt, ...) fprintf(stderr, "\e[47m🐞\e[0m\e[31m " fmt "\e[0m\n", ##__VA_ARGS__);

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
    func->_instructions[count] = {_OP_RETURN, 255};
    func->_name = SQString::Create(_ss(vm), "fuzz");
    func->_sourcename = SQString::Create(_ss(vm), "fuzz");
    func->_stacksize = 1024;
    func->_varparams = 0;

    return SQClosure::Create(_ss(vm), func, _table(vm->_roottable)->GetWeakRef(OT_TABLE));
}

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
