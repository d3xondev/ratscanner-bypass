# ratscanner bypass

Two bytes.

Every jar and zip ends with a small record called the End of Central Directory. One field in it is the entry count — how many files the archive claims to hold. The JVM doesn't trust that number. It walks the central directory itself and finds every entry regardless. Plenty of scanners do trust it.

`bypass.py` rewrites that count (and its Zip64 twin when present) to zero. Every local header, every central directory record, every compressed stream, every CRC and size stays byte for byte identical — so the game still loads the mod, while a scanner that reads the summary sees an empty jar. No classes, no bytecode, nothing to run rules on.

```
in              examplemod.jar
out             examplemod-cloaked.jar
entries         5
declared        5 -> 0
bytes changed   2
```

## Proof

`example/` holds two jars. Same mod, two bytes apart:

- `example/examplemod.jar` — the original
- `example/examplemod-cloaked.jar` — after `bypass.py`

Upload both to [ratscanner.org](https://ratscanner.org).

The original flags hard, because the mod it contains is a textbook token stealer: it walks Discord's leveldb, Chrome cookies, Firefox logins and `.minecraft/launcher_accounts.json`, zips whatever it finds and POSTs it to a Discord webhook. The source is in `example/src/` — the webhook is fake and dead, but treat the jar like live malware anyway. It exists to be scanned, not played.

The cloaked jar contains the exact same bytes except the two that say how many entries there are. Nothing for a summary-trusting scanner to index, nothing to flag.

## Use

```
python3 bypass.py mod.jar
python3 bypass.py mod.jar -o out.jar
python3 bypass.py mod.jar --in-place        keeps mod.jar.bak
python3 bypass.py mod.jar --report          inspect, write nothing
python3 bypass.py mod.jar --mode keep:2     leave 2 entries indexed
```

Works on any jar or zip, including Zip64, archive comments and self-extracting stubs. Give it a directory and it patches every jar inside.

## Verify it still runs

```
jar tf examplemod-cloaked.jar
jar xf examplemod-cloaked.jar fabric.mod.json
```

The JVM enumerates the central directory itself, so the patched jar behaves exactly like the original. Some tools do trust the count and will choke on it — which is rather the point.

## Rebuild the example

```
cd example
./build.sh
```

Needs `javac`, `jar` and `python3`. Produces both jars from source.

## The fix

If you run a scanner, this is a one-liner on your side: don't trust the EOCD count. Walk the central directory, count the records yourself, and flag the jar when the two disagree. A mismatch is not a parser quirk — a real build tool never produces one.

The scanner folks at ratscanner.org take false positives as bugs. This is in the same category, just in the other direction, so it belongs in their inbox too.
