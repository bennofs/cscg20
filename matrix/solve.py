#!/usr/bin/env python3
import numpy as np
import matplotlib.pyplot as plt
import wave
import glob
from scipy import signal
from scipy.io import wavfile
from itertools import zip_longest


short_chunks = [5, 10, 15, 25, 30, 35, 45, 50, 55]
long_samples = 294013
short_samples = 247047


def group(n, iterable):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=0)


def load():
    global sample_rate, samples
    sample_rate, samples = wavfile.read("./matrix.wav")
    print(f"sample_rate {sample_rate}, samples {samples}")


def load_samples():
    samples = []
    for s in sorted(glob.glob("chunks/*.wav")):
        samples += [wavfile.read(s)[1]]
    return samples


def recover_sample_starts(data, window_size = 1024, threshold=1000):
    thresholded = data < threshold

    prev = -1
    for i in np.nonzero(thresholded)[0]:
        below = np.amax(data[i:i+window_size]) < threshold
        if below and prev == -1:
            prev = i
        if not below and prev != -1:
            yield i
            prev = -1


def split_hypothesis():
    prev = 0
    for i in range(60):
        chunk_name = f"chunks/{i:02}.wav"
        print("write chunk", chunk_name)

        l = short_samples if i in short_chunks else long_samples
        wavfile.write(chunk_name, sample_rate, samples[prev:prev+l])
        prev += l


def split_samples():
    prev = 0
    i = 0
    for idx in recover_sample_starts(samples):
        chunk_name = f"chunks/{i:02}.wav"
        print("write chunk", chunk_name)
        wavfile.write(chunk_name, sample_rate, samples[prev:idx])
        prev = idx
        i += 1


def write_datas():
    with open("datas/lsb16be.bin", "wb") as f:
        f.write(bytes(int("".join(str(b) for b in bs), 2) for bs in group(8, (k & 1 for k in samples))))

    with open("datas/lsb16le.bin", "wb") as f:
        f.write(bytes(int("".join(str(b) for b in bs)[::-1], 2) for bs in group(8, (k & 1 for k in samples))))

    raw = wave.open("matrix.wav").readframes(len(samples))
    with open("datas/lsb8be.bin", "wb") as f:
        f.write(bytes(int("".join(str(b) for b in bs), 2) for bs in group(8, (k & 1 for k in raw))))
    with open("datas/lsb8le.bin", "wb") as f:
        f.write(bytes(int("".join(str(b) for b in bs)[::-1], 2) for bs in group(8, (k & 1 for k in raw))))



if __name__ == '__main__':
    load()
