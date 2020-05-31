source ./solve.py
pi setup()

define optrace
  b *0x555555554c0b
  commands
    silent
    printf "%05d %x\n", *(int*)0x555555756040, $eax
    cont
  end
end

define bat
  break *0x555555554c0b if *(int*)0x555555756040 == $arg0
end

define nextb
  tbreak *0x555555554d33
  cont
end

# 123456789012345678901234567
