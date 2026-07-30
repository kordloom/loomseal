# Reference verifier

`loomverify.py` is a second, independent LoomSeal verifier written from `FORMAT.md` and
`schema/loomseal-bundle.schema.json` alone. It does not share code with the Go verifier. Its job
is to keep the format honest: CI runs it against every conformance vector, so the moment the Go
verifier and the spec drift apart, the two implementations disagree and the build fails.

## Run

```sh
pip install -r reference/requirements.txt

# Verify one bundle.
python3 reference/loomverify.py examples/audit.loomseal.json

# Run the whole conformance suite.
python3 reference/loomverify.py --vectors testdata/vectors
```

The verifier is offline and reads only the files named on the command line.
