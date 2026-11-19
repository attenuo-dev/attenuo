/-
The differential test's runner: reads the case file the Rust test wrote and prints the
model's answer to each case, one line per case, in the order of the file. A case the runner
cannot read gets `error: <why>` on its line. See `Attenuo/Cases.lean` for the format and
`scripts/check-lean-differential.sh` for the comparison.
-/
import Attenuo.Cases

def main (args : List String) : IO UInt32 := do
  let [path] := args | do
    IO.eprintln "usage: differential CASES-FILE"
    return 2
  let lines ← IO.FS.lines path
  let out ← IO.getStdout
  for line in lines do
    match Attenuo.Cases.runLine line with
    | .ok answer => out.putStrLn answer
    | .error e => out.putStrLn s!"error: {e}"
  out.flush
  return 0
