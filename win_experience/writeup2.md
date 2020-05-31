# win_experience2

In the first part of this challenge, we already found two interesting processes:

```
0x8173ec08 CSCG_Delphi.exe        1920   1524      1       29      0      0 2020-03-22 18:27:45 UTC+0000
0x816d8438 TrueCrypt.exe           200   1524      1       44      0      0 2020-03-22 18:28:02 UTC+0000
```

So truecrypt is running. Get some more info about truecrypt:

```
$ vol.py --profile WinXPSP3x86 -f memory.dmp truecryptsummary
Volatility Foundation Volatility Framework 2.6.1
Process              TrueCrypt.exe at 0x816d8438 pid 200
Service              truecrypt state SERVICE_RUNNING
Kernel Module        truecrypt.sys at 0xf7036000 - 0xf706d000
Symbolic Link        E: -> \Device\TrueCryptVolumeE mounted 2020-03-22 18:30:32 UTC+0000
Symbolic Link        Volume{93193a72-6c5c-11ea-a09c-080027daee79} -> \Device\TrueCryptVolumeE mounted 2020-03-22 18:28:42 UTC+0000
Symbolic Link        E: -> \Device\TrueCryptVolumeE mounted 2020-03-22 18:30:32 UTC+0000
File Object          \Device\TrueCryptVolumeE\$LogFile at 0x16d9c48
File Object          \Device\TrueCryptVolumeE\$BitMap at 0x1706100
File Object          \Device\TrueCryptVolumeE\password.txt at 0x1717be8
File Object          \Device\TrueCryptVolumeE\$Directory at 0x1718190
File Object          \Device\TrueCryptVolumeE\$Mft at 0x1797e80
File Object          \Device\TrueCryptVolumeE\$MftMirr at 0x185cb80
File Object          \Device\TrueCryptVolumeE\flag.zip at 0x1a3c7e8
File Object          \Device\TrueCryptVolumeE\$Mft at 0x1a85940
File Object          \Device\TrueCryptVolumeE\$Directory at 0x1ae55a0
Driver               \Driver\truecrypt at 0x19d0b10 range 0xf7036000 - 0xf706cb80
Device               TrueCryptVolumeE at 0x8172fa48 type FILE_DEVICE_DISK
Container            Path: \??\C:\Program Files\TrueCrypt\true.dmp
Device               TrueCrypt at 0x816d4be0 type FILE_DEVICE_UNKNOWN
```

Dump the files `password.txt` and `flag.zip`:

```
$ vol.py --profile WinXPSP3x86 -f memory.dmp dumpfiles -Q 0x1717be8 --dump-dir .
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x01717be8   None   \Device\TrueCryptVolumeE\password.txt
$ vol.py --profile WinXPSP3x86 -f memory.dmp dumpfiles -Q 0x1a3c7e8 --dump-dir .
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x01a3c7e8   None   \Device\TrueCryptVolumeE\flag.zip
```

Unzip the flag and print it:

```
$ 7z x -y -p(cat file.None.0x81a8ffa0.dat) file.None.0x81732ef8.dat; cat flag.txt

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=de_DE.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs Intel(R) Core(TM) i5-6200U CPU @ 2.30GHz (406E3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 4096 bytes (4 KiB)

Extracting archive: file.None.0x81732ef8.dat

WARNINGS:
There are data after the end of archive

--
Path = file.None.0x81732ef8.dat
Type = zip
WARNINGS:
There are data after the end of archive
Physical Size = 253
Tail Size = 3843

Everything is Ok

Archives with Warnings: 1

Warnings: 1
Size:       53
Compressed: 4096
CSCG{c4ch3d_p455w0rd_fr0m_0p3n_tru3_cryp1_c0nt41n3r5}⏎  
```

## Mitigation
Cached files will always be in RAM, so leakage here is not really preventable. If you really want to keep something secret, reboot after using the file and then don't unlock the container on the next boot. This should make sure that the passphrase is no longer in RAM, and the file is only in RAM as long as you're actively using it.
