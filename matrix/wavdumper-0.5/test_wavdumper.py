import StringIO
import sys
import unittest

import wavdumper

"""
Test cases for Wavdumper. This doesn't test all features.
Any change (say, indentation amount or wording) in the output of Wavdumper
requires updates to test cases.

This test script is in main directory, even though it would be more
logical to put it in test/. This makes sure that 'import wavdumper' works;
otherwise, it wouldn't work _unless_ the users puts it along Python search
path, which might not happen for a script-like program like Wavdumper.

Notes:
- Files needed: test/dummy, test/dummylong, test/empty, test/invalid.wav,
  test/test1.wav
- Make sure there is no file named nonex1st1ng in the directory.
  (Shouldn't be... :)
- invalid.wav is an invalid WAV file made with a hex editor, but wavdumper
  should still recognize it.
"""

KNOWN_OUTPUT = {
    'test/test1.wav': """\
File: test/test1.wav (1910 bytes)
Chunk at pos 20: id = "fmt ", length = 16 bytes
  Format Chunk
  Data format: Uncompressed PCM
  Channels: 1
  Sample rate: 8800 Hz
  Average bytes per sec: 17600
  Block align (bytes): 2
  Bits per sample: 16
Chunk at pos 44: id = "data", length = 1760 bytes
  1760 bytes sample data
  880 samples
  0.100 seconds
Chunk at pos 1812: id = "smpl", length = 60 bytes
  Sampler Chunk
  Manufacturer: 0
  Product: 0
  MIDI note (60=middle-C): 69 (A-5) +- 0.0%
  Sample loop
    Loop ID: 0
    Type: forward
    Range: 0 - 879
    Repeat: infinity
Chunk at pos 1880: id = "LIST", length = 30 bytes
  List Chunk, id = "INFO"
  Chunk at pos 1892: id = "INAM", length = 17 bytes
    Name: 440 Hz sine wave""",

    'test/invalid.wav': """\
File: test/invalid.wav (12 bytes)
Warning: incorrect RIFF header length (256)""",

    'test/empty': """\
File: test/empty (0 bytes)
Not a WAV file""",

    'test/dummy': """\
File: test/dummy (5 bytes)
Not a WAV file""",

    'test/dummylong': """\
File: test/dummylong (39 bytes)
Not a WAV file""",

    # test is an existing directory
    'test': """\
Could not open test""",

    'nonex1st1ng': """\
Could not open nonex1st1ng""",
}

class WavdumpTest(unittest.TestCase):

    def testKnownOutput(self):
        """Test output for known values."""
        for filename in KNOWN_OUTPUT:
            outfile = StringIO.StringIO()
            wav = wavdumper.Wav(filename)
            wav.printInfo(outfile)
            output = outfile.getvalue().strip('\r\n')
            outfile.close()
            self.failUnless(output==KNOWN_OUTPUT[filename].strip(), 'Fail for %s' % filename)

    def testStdout(self):
        """Test that printInfo with no parameters prints to sys.stdout."""
        FILENAME = 'test/dummy'
        oldStdout = sys.stdout
        sys.stdout = StringIO.StringIO()
        wav = wavdumper.Wav(FILENAME)
        wav.printInfo()
        output = sys.stdout.getvalue().strip('\r\n')
        sys.stdout.close()
        sys.stdout = oldStdout
        self.failUnless(output==KNOWN_OUTPUT[FILENAME].strip(), 'Fail for %s' % FILENAME)

    def testSeveralRuns(self):
        """Test that printInfo can be called several times for the same Wav object."""
        FILENAME = 'test/test1.wav'

        wav = wavdumper.Wav(FILENAME)

        outfile1 = StringIO.StringIO()
        wav.printInfo(outfile1)
        output1 = outfile1.getvalue()
        outfile1.close()
        del outfile1

        outfile2 = StringIO.StringIO()
        wav.printInfo(outfile2)
        output2 = outfile2.getvalue()
        outfile2.close()

        self.failUnless(output1==output2)

def main(args):
    unittest.main()

if __name__=='__main__':
    main(sys.argv[1:])
