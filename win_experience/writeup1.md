## win_experience1

We're given a memory image. Let's first figure out the running processes:

```
$ vol.py --profile WinXPSP3x86 -f memory.dmp pslist
Volatility Foundation Volatility Framework 2.6.1
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
... some other uninteresting stuff ...
0x8173ec08 CSCG_Delphi.exe        1920   1524      1       29      0      0 2020-03-22 18:27:45 UTC+0000
0x816d8438 TrueCrypt.exe           200   1524      1       44      0      0 2020-03-22 18:28:02 UTC+0000
```

Ok, that CSCG_Delphi.exe' looks interesting. Extract it:

```
$ vol.py --profile WinXPSP3x86 -f memory.dmp dumpproc -p 1920
Volatility Foundation Volatility Framework 2.6.1
Process(V) ImageBase  Name                 Result
---------- ---------- -------------------- ------
0x8173ec08 0x00400000 CSCG_Delphi.exe      OK: executable.1920.exe
```

Searching for `flag` in the strings and then looking at XREFS finds this function (excerpt):

```
if ( *flag == 'C' )
{
    System::__linkproc__ LStrAsg(&hex1, &str_25DB3350B389538[1]);
    if ( flag[2] == 'C' && flag[3] == 'G' )
    {
    System::__linkproc__ LStrAsg(&hex2, &str_C129BD7796F23B9[1]);
    if ( flag[1] == 'S' )
    {
        System::__linkproc__ LStrAsg(&hex3, &str_40A00CA65772D7D[1]);
        if ( flag[4] == '{' )
        {
        System::__linkproc__ LStrAsg(&hex4, &str_017EFBC5B1D3FB2[1]);
        if ( flag[flen - 1] == '}' )
        {
            v4 = flen;
            if ( flen > 0 )
            {
            dword_458DEC = 1;
            do
            {
                if ( flag[dword_458DEC - 1] == '_' )
                ++underscoreCount;
                ++dword_458DEC;
                --v4;
            }
            while ( v4 );
            }
            if ( underscoreCount == 4 )
            {
            correctflag = -1;
            Compprod::TComponentsPageProducer::HandleTag(
                (Compprod::TComponentsPageProducer *)flag,
                6,
                (Classes::TStrings *)(flen - 6));
            System::__linkproc__ LStrAsg(&flag, v17);
            v5 = underscoreCount + 1;
            if ( underscoreCount + 1 > 0 )
            {
                dword_458DF0 = 1;
                do
                {
                dword_458DEC = findSubstringPos(&str___5[1], flag, 1);
                flaglen = strlen((int)flag);
                if ( !dword_458DEC )
                    dword_458DEC = flaglen + 1;
                getSubstring((int)flag, dword_458DEC - 1, (int)&v16);
                System::__linkproc__ LStrAsg(&dword_458DF4, v16);
                sub_4252C8(dword_458DF4, &v15);
                System::__linkproc__ LStrAsg(&dword_458DF4, v15);
                unknown_libname_771(hasher, dword_458DF4, &v13);
                Idhash::TIdHash128::AsHex(*(_DWORD *)hasher, &v13, &v14);
                System::__linkproc__ LStrAsg(&dword_458DE4, v14);
                System::__linkproc__ LStrCmp(dword_458DF8[dword_458DF0], dword_458DE4);
                if ( !v6 )
                    correctflag = 0;
                getSubstring2(flag, flaglen - dword_458DEC, &v12);
                System::__linkproc__ LStrAsg(&flag, v12);
                ++dword_458DF0;
                --v5;
                }
                while ( v5 );
            }
            }
        }
        }
    }
    }
}
}
```

The referenced strings are (reversed the hashes using online hash lookup tools):

```
1EFC99B6046A0F2C7E8C7EF9DC416323 dl0
C129BD7796F23B97DF994576448CAA23 l00hcs
017EFBC5B1D3FB2D4BE8A431FA6D6258 1hp13d
25DB3350B38953836C36DFB359DB4E27 kc4rc
40A00CA65772D7D102BB03C3A83B1F91 !3m
```

In the correct order (found by trying a few sensible ones), they give `CSCG{0ld_sch00l_d31ph1_cr4ck_m3!}`, the flag.

## Mitigation

Don't let your memory be dumped? Seriously, if you have secret flags in RAM, don't let your RAM be captured.

