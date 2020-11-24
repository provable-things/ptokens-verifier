## Python 

### Usage

```bash
$ ./verify tests/res/strongbox.proof 529305b4094a51b86207431a287d82419c242f0d9100f488a65e30a939e40135 1de35be63eaea67abc3f52fefdd684ee39145430ffb60fa940d9814fdef7d9fe  
```

When the above exits with code 0 means the proof has passed, 1 otherwise.

### Test

```bash
python -m pytest
```