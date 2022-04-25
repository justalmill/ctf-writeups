import sys
import os
import random
import struct
X13 = 1024*1024
X14 = 10 # 10 registers r0 -> r9
X15 = 2000
X16 = 55 
class Instruction:
    op = None
    imm = 0
    X11 = None
    X12 = None
    dsp = None
    X08 = None
    X10 = 0
    X02 = 0
    def __init__(self, tstr):
        def X06(tt):
            if tt.startswith("0x"):
                try:
                    v = int(tt, 16)
                except ValueError:
                    assert False
            else:
                try:
                    v = int(tt)
                except ValueError:
                    assert False
            assert v>=0
            assert v<pow(2,32)
            return v
        def X17_X08(tt):
            try:
                v = int(tt)
            except ValueError:
                assert False
            assert v>-1000
            assert v<1000
            return v
        def X07(tt):
            assert len(tt) == 2
            assert tt[0] == "r"
            try:
                v = int(tt[1])
            except ValueError:
                assert False
            assert v>=0
            assert v<X14
            return v
        def X17_memory(tt):
            try:
                v = int(tt)
            except ValueError:
                assert False
            assert v>=0
            assert v<X13
            return v
        assert len(tstr)<100 # instruction must be shorter than 100 characters
        sstr = tstr.split() # splits on spaces?
        assert len(sstr)>=1 # entries after split >= 1 and <= 4  =>> 1->4 spaces in instruction
        assert len(sstr)<=4
        if len(sstr) == 1:
            t_op = sstr[0]
            assert t_op in ["halt", "time", "magic", "reset"]
            self.op = t_op
        elif len(sstr) == 2:
            t_op, t_1 = sstr
            assert t_op in ["jmp", "jmpz"]
            self.op = t_op
            if self.op == "jmp":
                self.X08 = X17_X08(t_1)
            elif self.op == "jmpz":
                self.X08 = X17_X08(t_1)
            else:
                assert False
        elif len(sstr) == 3:
            t_op, t_1, t_2 = sstr
            assert t_op in ["mov", "movc", "jmpg", "add", "sub", "mul", "and", "or", "xor"]
            self.op = t_op
            if self.op == "mov":
                self.X11 = X07(t_1)
                self.X12 = X07(t_2)
            elif self.op in ["add", "sub", "mul", "and", "or", "xor"]:
                self.X11 = X07(t_1)
                self.X12 = X07(t_2)
            elif self.op == "movc":
                self.X11 = X07(t_1)
                self.imm = X06(t_2)
            elif self.op == "jmpg":
                self.X08 = X17_X08(t_2)
                self.X11 = X07(t_1)
            else:
                assert False
        elif len(sstr) == 4:
            t_op, t_1, t_2, t_3 = sstr
            assert t_op in ["movfrom", "movto"]
            self.op = t_op
            if self.op == "movfrom":
                self.X11 = X07(t_1) # register
                self.X10 = X17_memory(t_2) # memory address?
                self.dsp = X07(t_3) # register
            elif self.op == "movto":
                self.X11 = X07(t_1)
                self.X10 = X17_memory(t_2)
                self.dsp = X07(t_3)
            else:
                assert False
        else:
            assert False
    def pprint(self):
        tstr = "%s %s %s %s %s %s" %            (self.op, 
            "None" if self.X11==None else "r%d"%self.X11,
            "None" if self.X12==None else "r%d"%self.X12,
            hex(self.imm), "None" if self.X08==None else self.X08, self.X10)
        return tstr
class Cpu:
    rip = 0
    instructions = None
    registers = None
    memory = None
    max_instr_per_reset = 0
    dict_store = None
    execution_number = 0
    random_vals = None
    def __init__(self):
        self.instructions = []
        self.dict_store = {}
        self.random_vals = (random.randint(1,4200000000), random.randint(1,4200000000) , random.randint(1,4200000000), random.randint(1,4200000000))
        print("random:", self.random_vals)
        self.reset()
    def reset(self):
        self.rip = 0
        self.registers = [0 for r in range(X14)]
        print(len(self.registers), X14)
        self.memory = [0 for _ in range(X13)]
        print(len(self.memory), X13)
        self.max_instr_per_reset = 0
        print("before reset", self.dict_store)
        for k in self.dict_store.keys():
            self.dict_store[k] = 0
        print("after reset", self.dict_store)
        self.execution_number += 1
        print(self.execution_number)
    def load_instructions(self, tt):
        for line in tt.split("\n"):
            if "#" in line:
                line = line.split("#")[0] # you can add comments
            line = line.strip()
            if not line:
                continue
            self.instructions.append(Instruction(line))
            assert len(self.instructions) <= X16 # max 55 instructions
    def run(self, debug=1):
        ins = self.instructions[0]
        for i,v in enumerate(self.random_vals):
            self.memory[i] = v # the random values are put into memory
        print("memory", self.memory[:20])
        while (self.rip>=0 and self.rip<len(self.instructions) and self.execution_number<4 and self.max_instr_per_reset<20000):
            ins = self.instructions[self.rip]
            self.execute(ins)
    def execute(self, ins):
        self.max_instr_per_reset += 1
        print(f"time: {self.max_instr_per_reset}, instr: {ins.op}, arg1 {ins.X11}, arg2 {ins.X12}, mem {ins.dsp}")
        if ins.op == "movc":
            self.registers[ins.X11] = ins.imm
            self.rip += 1
        elif ins.op == "magic":
            print("executing magic", self.execution_number)
            if self.execution_number == 2:
                print("passed 1st check", self.registers[0:4], self.random_vals, self.memory[:20]) # need first 4 registers equal to the random numbers in x04
                if tuple(self.registers[0:4]) == self.random_vals:
                    with open("flag.txt", "rb") as fp:
                        cc = fp.read()
                    cc = cc.strip()
                    cc = cc.ljust(len(self.registers)*4, b"\x00")
                    for i in range(len(self.registers)):
                        self.registers[i] = struct.unpack("<I", cc[i*4:(i+1)*4])[0]
            self.rip += 1
        elif ins.op == "reset":
            self.reset()
        elif ins.op == "halt":
            self.rip = len(self.instructions)
        elif ins.op == "time":
            self.registers[0] = self.max_instr_per_reset
            self.rip += 1
        elif ins.op == "jmp":
            nt = self.rip + ins.X08
            assert nt >=0 
            assert nt < len(self.instructions)
            self.rip = nt
        elif ins.op == "jmpz":
            if self.registers[0] == 0:
                nt = self.rip + ins.X08
                assert nt >=0 
                assert nt < len(self.instructions)
                self.rip = nt
            else:
                self.rip += 1
        elif ins.op == "jmpg":
            if self.registers[0] > self.registers[ins.X11]:
                nt = self.rip + ins.X08
                assert nt >=0 
                assert nt < len(self.instructions)
                self.rip = nt
            else:
                self.rip += 1
        elif ins.op == "mov":
            self.registers[ins.X11] = self.registers[ins.X12]
            self.rip += 1
        elif ins.op == "sub":
            v = self.registers[ins.X11] - self.registers[ins.X12]
            self.registers[ins.X11] = (v & 0xffffffff)
            self.rip += 1
        elif ins.op == "add":
            print("add", self.registers[ins.X11], self.registers[ins.X12])
            v = self.registers[ins.X11] + self.registers[ins.X12]
            self.registers[ins.X11] = (v & 0xffffffff)
            self.rip += 1
        elif ins.op == "mul":
            print("mul", self.registers[ins.X11], self.registers[ins.X12])
            v = self.registers[ins.X11] * self.registers[ins.X12]
            self.registers[ins.X11] = (v & 0xffffffff)
            self.rip += 1
        elif ins.op == "and":
            print("and", self.registers[ins.X11], self.registers[ins.X12])
            v = self.registers[ins.X11] & self.registers[ins.X12]
            self.registers[ins.X11] = (v & 0xffffffff)
            self.rip += 1
        elif ins.op == "or":
            v = self.registers[ins.X11] | self.registers[ins.X12]
            self.registers[ins.X11] = (v & 0xffffffff)
            self.rip += 1
        elif ins.op == "xor":
            v = self.registers[ins.X11] ^ self.registers[ins.X12]
            print("xor res:", v)
            self.registers[ins.X11] = (v & 0xffffffff)
            self.rip += 1
        elif ins.op == "movfrom":
            print("time:", self.max_instr_per_reset)
            X09 = ins.X10 + self.registers[ins.dsp] # instruction at offset of 3rd arg plus 2nd arg 
            #print("X09", X09)
            X09 = X09 % len(self.memory) 
            #print("X09-2", X09, self.dict_store)
            if X09 in self.dict_store: # if that instruction modulo the number of instructions is in the dict, set register equal to it
                v = self.dict_store[X09]
                v = (v & 0xffffffff)
                self.registers[ins.X11] = v
                self.rip += 1
            else: # otherwise set it into memory and the dictionary and run the instruction again
                print("test") 
                v = self.memory[X09] 
                self.dict_store[X09] = v
                self.execute(ins)
            print("regs:", self.registers)
        elif ins.op == "movto":
            X09 = ins.X10 + self.registers[ins.dsp] # val 3rd arg plus 2nd arg
            X09 = X09 % len(self.memory) # modulo memory space
            if X09 in self.dict_store:
                del self.dict_store[X09]
            v = (self.registers[ins.X11] & 0xffffffff)
            self.memory[X09] = v
            print("mem", self.memory[:8])
            self.rip += 1
        else:
            assert False
        return 
    def pprint(self, debug=2):
        tstr = ""
        tstr += "%d> "%self.rip
        tstr += "[%d] "%self.max_instr_per_reset
        tstrl = []
        for i,r in enumerate(self.registers):
            tstrl.append("r%d=%d"%(i,r))
        tstr += ",".join(tstrl)
        if debug>1:
            tstr += "\nM->"
            vv = []
            for i,v in enumerate(self.memory):
                if v!=0:
                    vv.append("%d:%d"%(i,v))
            tstr += ",".join(vv)
            tstr += "\nC->"
            tstr += repr(self.dict_store)
        return tstr
def main():
    print("Welcome to a very fast VM!")
    print("Give me your instructions.")
    print("To terminate, send 3 consecutive empty lines.")
    instructions = ""
    X18 = 0 # keeps track of if it should terminate
    while True:
        line = input()
        if not line.strip():
            X18 += 1
        else:
            X18 = 0
        instructions += line + "\n"
        if X18 >= 3 or len(instructions) > X15: # Max 2000 length program
            break
    c = Cpu()
    print("Parsing...")
    c.load_instructions(instructions)
    print("Running...")
    c.run()
    print("Done!")
    print("Registers: " + repr(c.registers))
    print("Dict: " + repr(c.dict_store))
    print("Rands: " + repr(c.random_vals))
    print("Mem: " + repr(c.memory[1000:1004]))
    print("Len: ", len(c.instructions))
    print("Goodbye.")
if __name__ == "__main__":
    sys.exit(main())