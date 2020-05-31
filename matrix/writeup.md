## stage 1

Open the wave file with sonic-visualizer and look at the spectrogram (see attachment).
It shows "The password is: Th3-R3D-P1ll?". Using our favorite tool "steghide", we can extract an image called "redpill.jpg" from the wave file:

```
$ steghide extract -v -sf matrix.wav
Enter passphrase: Th3-R3D-P1ll?
reading stego file "matrix.wav"... done
extracting data... done
checking crc32 checksum... ok
done
```

## stage 2
We can use google image search to find images similar to `redpill.png`. We find the original, unmodified image at <https://img.fotocommunity.com/oktoberfest-bei-nacht-mit-vollmond-05261355-dabf-4ba3-8fd3-cef78ebe9a74.jpg?height=1080>.

Using GIMP, we diff the image with redpill.png (see attachment). Interpreting the lights as binary (yellow 0, pink 1) results in "n!C3_PW?" as ASCII.

Running `binwalk redpill.png` reveals an embedded zip archive:

```
906949        0xDD6C5         Zip archive data, encrypted at least v1.0 to extract, compressed size: 38, uncompressed size: 26, name: secret.txt
907151        0xDD78F         End of Zip archive, footer length: 22
```

With the recovered password, we can extract the secret.txt from that zip file.

## stage 3
secret.txt contains: `6W6?BHW,#BB/FK[?VN@u2e>m8`. At first, we might think that this is some transposition cipher, since the initial pattern (`6W6?`) matches the flag prefix (`CSCG`). However, it turns out that this is simply base85 encoded. Decoding it results in the flag: CSCG{St3g4n0_M4s7eR}
