/-
Reading and running the cases of the differential test (`scripts/check-lean-differential.sh`).

The Rust test `crates/attenuo-core/tests/lean_differential.rs` writes one case per line: the
function, its arguments as space-separated tokens in prefix form, ` = ` and Rust's answer.
`runLine` evaluates the model, on the concrete instances of `Attenuo/Concrete.lean`, on the
part before ` = ` and returns the model's answer in the same words. The grammar:

```text
line   := fn args " = " answer
fn     := sat C V | implies C C | pmatch S S | pcovers S S
        | cpermits CAP CALL | ccovers CAP CAP | spermits SET CALL | scovers SET SET
        | atten SET SET RESULT
V      := null | true | false | i:<integer> | f:<f64 bits as a decimal u64>[:<display>] | S
S      := s:<chars>   (`\\` is `\`, `\s` a space, `\x` and six hex digits any code point)
C      := eq V | oneof <n> V... | prefix S | pathprefix S | range B B
B      := - | <integer>
L      := - | calls:<n>
CAP    := cap S S L <n> (S C)...
SET    := set <n> CAP...
CALL   := call S S <names ok: 0 or 1> <n> (S V)...
RESULT := - | SET        (the set Rust's `attenuate` returned)
answer := true | false | ok | ok:other-set | err:empty | err:not-covered
```

For `atten` the model answers `ok` when it succeeds with a set equal to Rust's (each member
canonically equal to one of the other's, both ways), `ok:other-set` when it succeeds with
another set.
-/
import Attenuo.Concrete

namespace Attenuo.Cases

/-! ## Tokens -/

/-- A hex digit's value. -/
def hexVal (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
  else none

/-- The value of a list of hex digits. -/
def hexNat (cs : List Char) : Option Nat :=
  cs.foldlM (fun acc c => (hexVal c).map (acc * 16 + ·)) 0

/-- Undo the string escapes. -/
def unescape : List Char → Except String Str
  | [] => .ok []
  | '\\' :: '\\' :: rest => ('\\' :: ·) <$> unescape rest
  | '\\' :: 's' :: rest => (' ' :: ·) <$> unescape rest
  | '\\' :: 'x' :: a :: b :: c :: d :: e :: f :: rest =>
    match hexNat [a, b, c, d, e, f] with
    | some n =>
      if n.isValidChar then (Char.ofNat n :: ·) <$> unescape rest
      else .error s!"not a code point: {n}"
    | none => .error "bad \\x escape"
  | '\\' :: _ => .error "bad escape"
  | c :: rest => (c :: ·) <$> unescape rest

/-- The parser state: the tokens still to read. -/
abbrev P := StateT (List String) (Except String)

def next : P String := do
  match ← get with
  | [] => throw "unexpected end of case"
  | t :: ts => set ts; pure t

def expect (w : String) : P Unit := do
  let t ← next
  unless t == w do throw s!"expected {w}, got {t}"

def parseNat (t : String) : P Nat :=
  match t.toNat? with
  | some n => pure n
  | none => throw s!"not a natural number: {t}"

def parseInt (t : String) : P Int :=
  match t.toInt? with
  | some n => pure n
  | none => throw s!"not an integer: {t}"

def str : P Str := do
  let t ← next
  if t.startsWith "s:" then
    match unescape (t.drop 2).toString.toList with
    | .ok s => pure s
    | .error e => throw e
  else throw s!"expected a string, got {t}"

/-! ## Floats -/

/-- The value of an IEEE double from its bits, as `(negative, mantissa, exponent)` with the
value `mantissa * 2^exponent`, or `none` for an infinity or a NaN. -/
def decodeF64 (bits : Nat) : Option (Bool × Nat × Int) :=
  let neg : Bool := bits / 2 ^ 63 % 2 == 1
  let ex : Nat := bits / 2 ^ 52 % 2 ^ 11
  let frac : Nat := bits % 2 ^ 52
  if ex = 2047 then none
  else if ex = 0 then some (neg, frac, -1074)
  else some (neg, frac + 2 ^ 52, (ex : Int) - 1075)

/-- The model's value of a Rust `f64`: `wfloat` when the double is whole and its canonical
text has no exponent, else `ofloat`. -/
def floatValue (bits : Nat) : Except String JVal := do
  let some (neg, m, e) := decodeF64 bits | throw "a float that is not finite"
  -- The integer value, when the double is whole.
  let whole : Option Nat :=
    if e ≥ 0 then some (m * 2 ^ e.toNat)
    else if m % 2 ^ (-e).toNat = 0 then some (m / 2 ^ (-e).toNat) else none
  match whole with
  | some d =>
    let k := shortestDigits d
    if k < expThreshold then
      let key : Int := if neg then -(k : Int) else k
      if h : hasFloat key = true then pure (.wfloat key h)
      else throw s!"the double {d} is written as {k}, which hasFloat refuses"
    else pure (.ofloat bits)
  | none => pure (.ofloat bits)

/-! ## Values, constraints, capabilities -/

def value : P JVal := do
  let t ← next
  if t == "null" then pure .null
  else if t == "true" then pure (.bool true)
  else if t == "false" then pure (.bool false)
  else if t.startsWith "i:" then pure (.int (← parseInt (t.drop 2).toString))
  else if t.startsWith "f:" then
    let bits := ((t.drop 2).toString.splitOn ":").headD ""
    match floatValue (← parseNat bits) with
    | .ok v => pure v
    | .error e => throw e
  else if t.startsWith "s:" then
    set (t :: (← get))
    pure (.str (← str))
  else throw s!"expected a value, got {t}"

def bound : P (Option Int) := do
  let t ← next
  if t == "-" then pure none else some <$> parseInt t

def constraint : P (Constraint JVal) := do
  let t ← next
  match t with
  | "eq" => .equals <$> value
  | "oneof" =>
    let n ← parseNat (← next)
    let mut vs := #[]
    for _ in List.range n do
      vs := vs.push (← value)
    pure (.oneOf vs.toList)
  | "prefix" => .strPrefix <$> str
  | "pathprefix" => .pathPrefix <$> str
  | "range" => do
    let lo ← bound
    let hi ← bound
    pure (.range lo hi)
  | _ => throw s!"expected a constraint, got {t}"

def limits : P CallsLimit := do
  let t ← next
  if t == "-" then pure ⟨none⟩
  else if t.startsWith "calls:" then pure ⟨some (← parseNat (t.drop 6).toString)⟩
  else throw s!"expected limits, got {t}"

def capability : P (Capability JVal CallsLimit) := do
  expect "cap"
  let server ← str
  let tool ← str
  let l ← limits
  let n ← parseNat (← next)
  let mut cs := #[]
  for _ in List.range n do
    let arg ← str
    cs := cs.push (arg, ← constraint)
  pure { server, tool, constraints := cs.toList, limits := l }

def capSet : P (CapSet JVal CallsLimit) := do
  expect "set"
  let n ← parseNat (← next)
  let mut cs := #[]
  for _ in List.range n do
    cs := cs.push (← capability)
  pure cs.toList

def call : P (ToolCall JVal) := do
  expect "call"
  let server ← str
  let tool ← str
  let ok ← next
  let namesOk ← match ok with
    | "1" => pure true
    | "0" => pure false
    | _ => throw s!"expected 0 or 1, got {ok}"
  let n ← parseNat (← next)
  let mut args := #[]
  for _ in List.range n do
    let arg ← str
    args := args.push (arg, ← value)
  pure { server, tool, args := args.toList, namesOk }

/-! ## Comparing result sets -/

/-- Canonical equality of two constraints: what Rust's `ArgConstraint` `==` compares (their
RFC 8785 forms). -/
def constraintEq : Constraint JVal → Constraint JVal → Bool
  | .equals a, .equals b => decide (a.canon = b.canon)
  | .oneOf as, .oneOf bs =>
    as.length == bs.length && (as.zip bs).all (fun (a, b) => decide (a.canon = b.canon))
  | .strPrefix p, .strPrefix q => p == q
  | .pathPrefix p, .pathPrefix q => p == q
  | .range a b, .range c d => a == c && b == d
  | _, _ => false

/-- Equality of capabilities, as Rust's `Capability` `==` compares them. Both constraint
lists hold one entry per argument. -/
def capEq (a b : Capability JVal CallsLimit) : Bool :=
  a.server == b.server && a.tool == b.tool && a.limits == b.limits
  && a.constraints.length == b.constraints.length
  && a.constraints.all (fun (arg, c) =>
      match b.constraints.lookup arg with
      | some d => constraintEq c d
      | none => false)

/-- The same set: each member of one equals a member of the other. -/
def setEq (a b : CapSet JVal CallsLimit) : Bool :=
  a.all (fun x => b.any (capEq x)) && b.all (fun y => a.any (capEq y))

/-! ## Running a case -/

def showBool (b : Bool) : String := if b then "true" else "false"

/-- The model's answer to the case written by the tokens. -/
def run : P String := do
  let f ← next
  match f with
  | "sat" => do
    let c ← constraint
    let v ← value
    pure (showBool (c.sat v))
  | "implies" => do
    let c ← constraint
    let d ← constraint
    pure (showBool (c.implies d))
  | "pmatch" => do
    let p ← str
    let n ← str
    pure (showBool (patternMatches p n))
  | "pcovers" => do
    let p ← str
    let c ← str
    pure (showBool (patternCovers p c))
  | "cpermits" => do
    let c ← capability
    let k ← call
    pure (showBool (c.permits k))
  | "ccovers" => do
    let p ← capability
    let c ← capability
    pure (showBool (p.covers c))
  | "spermits" => do
    let s ← capSet
    let k ← call
    pure (showBool (CapSet.permits s k))
  | "scovers" => do
    let p ← capSet
    let c ← capSet
    pure (showBool (CapSet.covers p c))
  | "atten" => do
    let p ← capSet
    let r ← capSet
    let t ← next
    let rust ← if t == "-" then pure none else do
      set (t :: (← get))
      some <$> capSet
    match CapSet.attenuate p r with
    | .error .empty => pure "err:empty"
    | .error .notCovered => pure "err:not-covered"
    | .ok out =>
      match rust with
      | some s => pure (if setEq out s then "ok" else "ok:other-set")
      | none => pure "ok:other-set"
  | _ => throw s!"unknown function {f}"

/-- The model's answer to one case line, or why the line could not be read. -/
def runLine (line : String) : Except String String := do
  let body := (line.splitOn " = ").headD ""
  let toks := (body.splitOn " ").filter (· ≠ "")
  let (answer, rest) ← run.run toks
  unless rest.isEmpty do throw s!"trailing tokens: {rest}"
  pure answer

end Attenuo.Cases
