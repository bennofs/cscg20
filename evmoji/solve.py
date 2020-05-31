#!/usr/bin/env python3
import gdb
import angr
import claripy
import json
from angrgdb import *

# These addresses were obtained through static analysis
INTERPRETER_LOOP = 0x555555554bf0 # start of the interpreter loop. visited for each opcode
READ_CALL = 0x555555554eab        # call to read
POW_FUNC = 0x555555554a89         # plt entry for pow
PROGRAM_ADDR = 0x555555756040     # address of the `program` struct

class PowHook(angr.SimProcedure):
    """
    I have not investigated why, but pow in angr is broken somehow.
    Let's use GDB to execute it concretely.
    """
    def run(self, a, b):
        assert a.concrete, "first pow arg must be concrete"
        assert b.concrete, "second pow arg must be concrete"

        a = self.state.solver.eval(a)
        b = self.state.solver.eval(b)

        # call the function
        r = gdb.parse_and_eval(f'((int(*)(long,long)){POW_FUNC})({a}, {b})')
        self.state.mem[b].uint32_t = struct.unpack("I", gdb.inferiors()[0].read_memory(b, 4))[0]
        return int(r)


def gdb_setup():
    """
    This function starts a new run of the program.
    It will break before the `read` syscall.
    """
    gdb.execute("delete")
    gdb.execute(f"tbreak *{READ_CALL}")
    gdb.execute("r code.bin < fakeinput")


def setup():
    """
    Starts a new run, and extracts an angr state after `read` has been called.
    The address of the input buffer is stored in the global variable `bufaddr`,
    the size that was passed to read in `size`.

    The state after the read is stored in INIT_STATE.
    We also store a state with symbolized input in SIM_STATE.
    The input variable is stored in INPUT.
    """
    global bufaddr, size, INIT_STATE, SIM_STATE, INPUT
    gdb_setup()

    bufaddr = int(gdb.selected_frame().read_register("rsi"))
    size = int(gdb.selected_frame().read_register("rdx"))
    gdb.execute("ni")

    INIT_STATE = StateManager().state
    INIT_STATE.project.hook(POW_FUNC, PowHook())

    SIM_STATE = INIT_STATE.copy()
    INPUT = claripy.BVS("input", 8 * size)
    SIM_STATE.memory.store(bufaddr, INPUT)

def get_ip(state):
    """
    Extract the current instruction pointer of the emulated virtual machine
    from an angr state.
    """
    return state.mem[PROGRAM_ADDR].long.concrete


def angr_step(state):
    """
    Return the successors states after a single angr step, or bytes if we reached a write call.
    """
    write_addr = state.project.loader.main_object.plt["write"]
    if state.addr != write_addr:
        return state.step(extra_stop_points=[INTERPRETER_LOOP, write_addr]).successors

    addr = state.regs.rsi
    size = state.solver.eval(state.regs.rdx, cast_to=int)
    data = state.solver.eval(state.memory.load(addr, size), cast_to=bytes)
    return data


def angr_nextb(state):
    """
    Execute a state until the next branch that depends on input data (is symbolic).
    Only branches due to conditions in the emulated program are supported.

    Returns (s1, s2), where s1 is the state that didn't jump and s2 is the one that did (ip of s2 > ip of s1).
    If we hit a WRITE call, then return the written bytes instead.
    """
    # step until there's more than two successor states
    states = [state.copy()]
    while len(states) < 2:
        states = angr_step(states[0])
        if isinstance(states, bytes):
            return states

    # there should be exactly 2 successors
    if len(states) != 2:
        return b"branch too many"

    # sort the states by addr
    states = list(sorted(states, key=lambda x: x.addr))
    jump, normal = states

    # this verifies that the states actually branched at the 0x94a49ff0 vm opcode
    # the addresses past the branch end in 0xd39 and 0x15f
    if jump.addr & 0xfff != 0xd39 or normal.addr & 0xfff != 0x15f:
        return f"unexpected branch {repr(states)}".encode()

    # to ensure that both states are at the same RIP, step the state that took the jump one more time
    # after this, both states should be at addr ending in 0x15f
    succ = jump.step().successors
    if len(succ) != 1:
        print(jump)
        print(succ)
        print("expected one successors")
        return

    return normal, succ[0]


def angr_cfg(start):
    """
    Dynamically build a CFG of the emulated program starting in state `start`
    """
    todo = [start]
    graph = {}
    while todo:
        print(f"queue: {len(todo)}")

        # fetch the next state to process
        s = todo.pop()
        source = get_ip(s)

        # if we have already processed this state, continue
        if source in graph:
            continue

        # find possible successors
        targets = angr_nextb(s)
        graph[source] = targets

        # if this is final edge (WRITE call), don't do anything more
        if not isinstance(targets, tuple):
            continue

        # otherwise, add the newly found targets to the queue
        # if we haven't processed them yet
        todo = list(t for t in targets if get_ip(t) not in graph) + todo

    return graph


def cfg_dot(g):
    """
    Writes a control flow graph as dot file.
    """
    with open("graph.dot", "w") as f:
        f.write("digraph control_flow {\n")
        for source, targets in g.items():
            if not isinstance(targets, list) and not isinstance(targets, tuple):
                f.write(f'{source} -> {json.dumps(targets.decode())};\n')
            else:
                for target in targets:
                    f.write(f"{source} -> {get_ip(target)};\n")
        f.write("}")


def angr_step_to_loop(s):
    """
    Step a state forward until it is at the beginning of the interpreter loop
    """
    states = [s]
    while states[0].addr != INTERPRETER_LOOP:
        states = angr_step(states[0])
        if isinstance(states, bytes):
            return states

        if len(states) != 1:
            print(s)
            print(states)
            raise RuntimeError("cannot step to loop, branch")

    return states[0]


def angr_until(s, ip):
    """
    Step a state forward until the emulated vm is at the given instruction pointer
    """
    states = [s]
    while get_ip(states[0]) != ip:
        states = angr_step(states[0])

        if isinstance(states, bytes):
            return states

        if len(states) != 1:
            print(states[0])
            print(states)
            raise RuntimeError("branch during until")

    return angr_step_to_loop(states[0])


def angr_merge(a, b):
    """
    Merge two states after a branch in the emulated code.

    Since we don't want the virtual instruction pointer to become symbolic,
    we step both states forward until they reach a common point.
    At this point, we merge both of the states into one.

    This function assumes that both states a and b are directly after a branch opcode (0x94a49ff0)
    """
    # extract the condition that caused the branch
    cond = a.history.jump_guards[-1]

    # step forward until we reach a common point
    while get_ip(a) != get_ip(b):
        if get_ip(a) < get_ip(b):
            a = angr_until(a, get_ip(b))
            if isinstance(a, bytes):
                return a, b
        else:
            b = angr_until(b, get_ip(a))
            if isinstance(b, bytes):
                return a, b
    print("merge common", a, b, get_ip(a) , get_ip(b))

    # simplify before merging
    a.solver.simplify()
    b.solver.simplify()

    # verify that the condition actually separates both states
    if not a.solver.eval(cond) or b.solver.eval(cond):
        print("unexpected symbolic branch")
        print(cond)
        return

    # merge with our custom merge condition
    m = a.merge(b, merge_conditions=[
        [cond],
        [claripy.Not(cond)],
    ])[0]

    # simplify before returning the merged state
    m.solver.simplify()
    return m

STATES = []
WRITE_STATE = {}
def angr_explore_writes_merge(s):
    while True:
        STATES.append(s)
        print(len(STATES))
        n = angr_nextb(s)
        if isinstance(n, bytes):
            print(f"found state for write {repr(n)}")
            WRITE_STATE[n] = s
            break

        s = angr_merge(*n)
        if isinstance(s, tuple):
            if isinstance(s[0], bytes):
                print(f"found state for write {repr(s[0])}")
                WRITE_STATE[s[0]] = n[0]
                s = s[1]
            else:
                print(f"found state for write {repr(s[1])}")
                WRITE_STATE[s[1]] = n[1]
                s = s[0]


def run_cfg():
    global CFG
    CFG = angr_cfg(SIM_STATE)
    cfg_dot(CFG)


def solve():
    angr_explore_writes_merge(SIM_STATE)
    print(WRITE_STATE[b'Thats the flag: CSCG{'].solver.eval(INPUT, cast_to=bytes))
