handle all nostop
set pagination off

python
gdb.set_convenience_variable("gamebase", int([x for x in gdb.execute("info proc mappings", False, True).split("\n") if "Game" in x][0].split()[0],16))
end

# b *$gamebase+0x3C5091
# commands
# silent
# x/1hs $rdi+0x14
# continue
# end

# b *$gamebase+0x7D5D40
# commands
# silent
# x/1hs $rdi+0x14
# continue
# end

# set $emoji=0
# break *$gamebase+0x3C5020 if $rsi=22
# commands
# silent
# set $rsi=$emoji
# set $emoji=$emoji+1
# continue
# end

#break *$gamebase+0x421B83
#break *$gamebase+0x3C5536 xor decryption

source /code/gef/gef.py
gef config context.layout "legend regs stack code"

define enable_gravity
  set *(int*)($gamebase+0x003ac200)=0x56415741
end

define disable_gravity
  set *(int*)($gamebase+0x003ac200)=0xc3c3c3c3
end


define setSpeedFactor
  set $speedFactor=$arg0
  tbreak *$gamebase+0x3AB2E0
  commands
    silent
    set *(float*)($rax+0x24)=$speedFactor
    continue
  end
end

define getPosition
  set $rspSaved=$rsp
  set $rsp=((long)$rsp-0x100)&~0x3F
  set $result = (float*)($rsp+0x10)
  call (void)$getPositionFunc($getTransform($arg0), $result)
  printf "%f %f %f\n", $result[0], $result[1], $result[2]

  set $rsp=$rspSaved
end

define printVector
  set $addr=(float*)$arg0
  printf "%f %f %f\n", $addr[0], $addr[1], $addr[2]
end

define getPositions
  set $list=(long*)$arg0
  set $size=$list[3]
  set $idx=0
  while ($idx < $size)
    set $entry = $list[4 + $idx]
    getPosition $entry
    set $idx = $idx + 1
  end
end

define nextUpdate
  tbreak *$update
  commands
    set $sm = (long******************)$rdi
  end
  continue
end

set $getTransform=(*(long (**)(long))($gamebase+0x1138AF0))
set $getPositionFunc=(*(long (**)(long, long))($gamebase+0x11373E0))
set $update=$gamebase+0x3C80B0
