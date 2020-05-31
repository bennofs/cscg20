#!/usr/bin/env python3
import wave

with wave.open("./matrix.wav") as f:
    nframes = f.getnframes()
    print(f.readframes(f.getnframes()).hex())
