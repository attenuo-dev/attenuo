/-
Concrete instances of the two abstract classes, so that the model runs on the values Rust
handles: `JVal` for `JsonValue` (null, booleans, strings, integers and floats, as
`serde_json::Value` holds them, with the canonical equality of `jcs::value_eq`), and
`CallsLimit` for `LimitsModel` (a `Limits` that holds only `calls`).

Every class law is proven below for these instances. The differential test
(`scripts/check-lean-differential.sh`) runs the model on them against the Rust code.
-/
import Attenuo.Capability

namespace Attenuo

/-! ## Numbers

Rust compares two numbers by their canonical (RFC 8785) text: an integer is written with its
digits, a float with the shortest digits that read back as the same double (`format_f64`,
ECMAScript's `Number::toString`). A float is so equal to an integer exactly when it is whole,
below `10^21` (above that the text has an exponent), and its shortest digits are the integer's.
Each float has one text and each integer one, so the model keeps of a whole float below `10^21`
only that integer (`JVal.wfloat`), and of any other float only its identity (`JVal.ofloat`).

Which integers some double is written as is a fact about IEEE doubles and the shortest-digits
rule. `hasFloat` computes it the way `range_admits_all_equal` asks it: round the integer to the
nearest double and write that double's shortest digits. The class laws hold whatever
`hasFloat` computes (it only decides which `wfloat` values exist); that it computes what Rust
computes is what the differential test checks. -/

/-- `WHOLE_FLOAT_MAX`: the largest magnitude of a float that `as_long` reads as an integer. -/
def wholeFloatMax : Int := 922337203685477

/-- At most `WHOLE_FLOAT_MAX` in magnitude. -/
def small (n : Int) : Prop := -wholeFloatMax ≤ n ∧ n ≤ wholeFloatMax

instance (n : Int) : Decidable (small n) := inferInstanceAs (Decidable (_ ∧ _))

/-- Does the integer fit in `i64`? -/
def inI64 (n : Int) : Bool := decide (i64Min ≤ n ∧ n ≤ i64Max)

/-- The number of bits of `n` (0 for 0). -/
def bitLen (n : Nat) : Nat := if n = 0 then 0 else Nat.log2 n + 1

/-- The double nearest to the integer `n` (round half to even), as an integer. Every integer
below `2^53` is a double. -/
def nearestDouble (n : Nat) : Nat :=
  let b := bitLen n
  if b ≤ 53 then n
  else
    let s := b - 53
    let q := n / 2 ^ s
    let r := n % 2 ^ s
    let half := 2 ^ (s - 1)
    let q' := if r > half ∨ (r = half ∧ q % 2 = 1) then q + 1 else q
    q' * 2 ^ s

/-- The digits ECMAScript writes for the whole double `d`, read as an integer: among the
integers with the most trailing zeros that read back as `d` (the shortest digits), the one
nearest to `d`, ties to an even last digit. A double reads back from every real in the half
gap to its neighbours, the bounds included when its mantissa is even (round half to even);
the gap below a power of two is half the gap above. Below `2^53` the gap is at most 1 and the
answer is `d` itself. -/
def shortestDigits (d : Nat) : Nat :=
  let b := bitLen d
  if b ≤ 53 then d
  else
    -- d = m * 2^e with 2^52 ≤ m < 2^53; all quantities are scaled by 4 to stay whole.
    let e := b - 53
    let m := d / 2 ^ e
    let up := 2 ^ (e + 1)
    let down := if m = 2 ^ 52 then 2 ^ e else 2 ^ (e + 1)
    let incl := m % 2 = 0
    let inside (c : Nat) : Bool :=
      decide ((4 * c + down > 4 * d ∨ (incl ∧ 4 * c + down = 4 * d))
        ∧ (4 * c < 4 * d + up ∨ (incl ∧ 4 * c = 4 * d + up)))
    let pick (j : Nat) : Option Nat :=
      let p := 10 ^ j
      let q := d / p
      let c1 := q * p
      let c2 := (q + 1) * p
      match inside c1, inside c2 with
      | true, true =>
        if d - c1 < c2 - d then some c1
        else if c2 - d < d - c1 then some c2
        else if q % 2 = 0 then some c1 else some c2
      | true, false => some c1
      | false, true => some c2
      | false, false => none
    ((List.range 26).reverse.findSome? pick).getD d

/-- `10^21`: from here on a double is written with an exponent. -/
def expThreshold : Nat := 10 ^ 21

/-- Is the integer `n` the canonical text of some double? Rust's question in
`range_admits_all_equal`: `format_f64(n as f64) == n.to_string()`. -/
def hasFloat (n : Int) : Bool :=
  n.natAbs < expThreshold && shortestDigits (nearestDouble n.natAbs) == n.natAbs

/-! ## Values -/

/-- A JSON value as far as constraints look at it. Arrays and objects are left out. -/
inductive JVal where
  | null
  | bool (b : Bool)
  | str (s : Str)
  /-- A JSON integer, as `serde_json` holds one (an `i64` or a `u64`). -/
  | int (n : Int)
  /-- A float whose canonical text is the integer `k` (`5.0` is `wfloat 5`; the double
  `2^60` is `wfloat 1152921504606847000`). -/
  | wfloat (k : Int) (h : hasFloat k = true)
  /-- Any other finite float (a fraction, or a magnitude of at least `10^21`), by its bits.
  It is canonically equal only to itself. -/
  | ofloat (bits : Nat)
  /-- Not a Rust value: an integer outside `i64` as `Value::from` would make it if it took
  one. The class asks `ofLong n` to read back as `n` for every integer `n`, and Rust's
  `Value::from(i64)` takes only `i64`. These values are never generated. -/
  | big (n : Int)

/-- The canonical form `value_eq` compares. -/
inductive Canon where
  | null
  | bool (b : Bool)
  | str (s : Str)
  | num (n : Int)
  | flt (bits : Nat)
  | big (n : Int)
deriving DecidableEq

namespace JVal

def canon : JVal → Canon
  | .null => .null
  | .bool b => .bool b
  | .str s => .str s
  | .int n => .num n
  | .wfloat k _ => .num k
  | .ofloat b => .flt b
  | .big n => .big n

/-- `Value::as_str`. -/
def asStr : JVal → Option Str
  | .str s => some s
  | _ => none

/-- `as_long`: an `i64` integer, or a whole float of magnitude at most `WHOLE_FLOAT_MAX`. -/
def asLong : JVal → Option Int
  | .int n => if inI64 n then some n else none
  | .wfloat k _ => if small k then some k else none
  | .big n => if inI64 n then none else some n
  | _ => none

/-- `Value::from(i64)`. -/
def ofLong (n : Int) : JVal := if inI64 n then .int n else .big n

/-- `range_admits_all_equal` for the range `[lo, hi]`: `a` is an integer in the range, and
when it is an integer above `WHOLE_FLOAT_MAX` in magnitude, no float is written as it. -/
def admitsAllEqual (lo hi : Int) : JVal → Bool
  | .int n => inI64 n && decide (lo ≤ n ∧ n ≤ hi)
      && (decide (small n) || !hasFloat n)
  | .wfloat k _ => decide (small k ∧ lo ≤ k ∧ k ≤ hi)
  | .big n => !inI64 n && decide (lo ≤ n ∧ n ≤ hi)
  | _ => false

theorem canon_eq_num {v : JVal} {n : Int} (h : v.canon = .num n) :
    v = .int n ∨ ∃ hf, v = .wfloat n hf := by
  cases v with
  | int m => simp only [canon, Canon.num.injEq] at h; exact Or.inl (h ▸ rfl)
  | wfloat k hk =>
    simp only [canon, Canon.num.injEq] at h
    subst h
    exact Or.inr ⟨hk, rfl⟩
  | _ => simp [canon] at h

theorem canon_eq_big {v : JVal} {n : Int} (h : v.canon = .big n) : v = .big n := by
  cases v <;> simp_all [canon]

theorem small_inI64 {k : Int} (h : small k) : inI64 k = true := by
  simp only [small, wholeFloatMax] at h
  unfold inI64
  rw [decide_eq_true_iff]
  simp only [i64Min, i64Max]
  omega

theorem admitsAllEqual_iff (lo hi : Int) (a : JVal) : admitsAllEqual lo hi a = true ↔
    ∀ v : JVal, decide (v.canon = a.canon) = true →
      ∃ n, v.asLong = some n ∧ lo ≤ n ∧ n ≤ hi := by
  constructor
  · intro h v hv
    simp only [decide_eq_true_eq] at hv
    cases a with
    | int n =>
      have h1 : inI64 n = true := by
        revert h; simp only [admitsAllEqual]; cases inI64 n <;> simp
      have h2 : lo ≤ n ∧ n ≤ hi := by
        revert h; simp only [admitsAllEqual]; cases inI64 n <;> simp_all
      have h3 : small n ∨ hasFloat n = false := by
        revert h; simp only [admitsAllEqual]; cases hasFloat n <;> simp_all
      rcases canon_eq_num hv with rfl | ⟨hf, rfl⟩
      · exact ⟨n, by simp [asLong, h1], h2⟩
      · rcases h3 with hs | hs
        · exact ⟨n, by simp [asLong, hs], h2⟩
        · simp [hs] at hf
    | wfloat k hk =>
      simp only [admitsAllEqual, decide_eq_true_eq] at h
      obtain ⟨hs, hr⟩ := h
      rcases canon_eq_num hv with rfl | ⟨hf, rfl⟩
      · exact ⟨k, by simp [asLong, small_inI64 hs], hr⟩
      · exact ⟨k, by simp [asLong, hs], hr⟩
    | big n =>
      simp only [admitsAllEqual, Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq] at h
      rw [canon_eq_big hv]
      exact ⟨n, by simp [asLong, h.1], h.2⟩
    | _ => simp [admitsAllEqual] at h
  · intro h
    have hself := h a (by simp)
    obtain ⟨n, hn, hr⟩ := hself
    cases a with
    | int m =>
      simp only [asLong] at hn
      split at hn
      · next hi64 =>
        simp only [Option.some.injEq] at hn
        subst hn
        have hor : decide (small m) = true ∨ hasFloat m = false := by
          by_cases hs : small m
          · exact Or.inl (by simp [hs])
          · right
            cases hf : hasFloat m
            · rfl
            · obtain ⟨n', hn', _⟩ := h (.wfloat m hf) (by simp [canon])
              simp [asLong, hs] at hn'
        simp only [admitsAllEqual, hi64, Bool.true_and]
        rcases hor with hs | hs <;> simp [hs, hr]
      · simp at hn
    | wfloat k hk =>
      simp only [asLong] at hn
      split at hn
      · next hs =>
        simp only [Option.some.injEq] at hn
        subst hn
        simp [admitsAllEqual, hs, hr]
      · simp at hn
    | big m =>
      simp only [asLong] at hn
      split at hn
      · simp at hn
      · next hi64 =>
        simp only [Option.some.injEq] at hn
        subst hn
        simp [admitsAllEqual, hi64, hr]
    | _ => simp [asLong] at hn

end JVal

instance jsonValueJVal : JsonValue JVal where
  veq a b := decide (a.canon = b.canon)
  veq_refl a := by simp
  veq_symm h := by simp_all
  veq_trans h1 h2 := by simp_all
  asStr := JVal.asStr
  asStr_congr {a b} h := by
    simp only [decide_eq_true_eq] at h
    cases a <;> cases b <;> simp_all [JVal.canon, JVal.asStr]
  ofStr := .str
  asStr_ofStr _ := rfl
  asLong := JVal.asLong
  ofLong := JVal.ofLong
  asLong_ofLong n := by
    unfold JVal.ofLong
    split <;> simp_all [JVal.asLong]
  asStr_ofLong n := by
    unfold JVal.ofLong
    split <;> rfl
  veq_ofLong {v n} h := by
    simp only [decide_eq_true_eq]
    cases v with
    | int m =>
      simp only [JVal.asLong] at h
      split at h
      · next hi =>
        simp only [Option.some.injEq] at h
        subst h
        simp [JVal.ofLong, hi, JVal.canon]
      · simp at h
    | wfloat k hk =>
      simp only [JVal.asLong] at h
      split at h
      · next hs =>
        simp only [Option.some.injEq] at h
        subst h
        simp [JVal.ofLong, JVal.small_inI64 hs, JVal.canon]
      · simp at h
    | big m =>
      simp only [JVal.asLong] at h
      split at h
      · simp at h
      · next hi =>
        simp only [Option.some.injEq] at h
        subst h
        simp [JVal.ofLong, hi, JVal.canon]
    | _ => simp [JVal.asLong] at h
  admitsAllEqual := JVal.admitsAllEqual
  admitsAllEqual_iff := JVal.admitsAllEqual_iff

/-! ## Limits with only `calls` -/

/-- A `Limits` holding at most a `calls` figure (`sum`, `calls_per` and `distinct` absent). -/
structure CallsLimit where
  calls : Option Nat
deriving DecidableEq

/-- `Limits::narrows` with only `calls`: when the parent has a figure, the child has one no
larger. -/
def CallsLimit.narrows (child parent : CallsLimit) : Bool :=
  match parent.calls with
  | none => true
  | some p =>
    match child.calls with
    | some c => decide (c ≤ p)
    | none => false

/-- `Limits::clamp_to` with only `calls`: the parent's figure when the child has none, else
the smaller of the two. -/
def CallsLimit.clampTo (child parent : CallsLimit) : CallsLimit :=
  match parent.calls with
  | none => child
  | some p =>
    match child.calls with
    | some c => ⟨some (min c p)⟩
    | none => ⟨some p⟩

instance limitsModelCallsLimit : LimitsModel CallsLimit where
  narrows := CallsLimit.narrows
  narrows_refl l := by
    unfold CallsLimit.narrows
    cases l.calls <;> simp
  narrows_trans {a b c} hab hbc := by
    unfold CallsLimit.narrows at *
    cases hc : c.calls with
    | none => rfl
    | some z =>
      rw [hc] at hbc
      cases hb : b.calls with
      | none => simp [hb] at hbc
      | some y =>
        rw [hb] at hbc hab
        cases ha : a.calls with
        | none => simp [ha] at hab
        | some x =>
          rw [ha] at hab
          simp only [decide_eq_true_eq] at hab hbc ⊢
          omega
  clampTo := CallsLimit.clampTo

/-! ## The theorems on these instances

The theorems hold for every instance, so for these; stated here for the types the
differential test runs. -/

/-- `CapSet.covers_sound` on the concrete values and limits. -/
theorem concrete_covers_sound {p c : CapSet JVal CallsLimit} (h : CapSet.covers p c = true)
    {call : ToolCall JVal} (hc : CapSet.permits c call = true) : CapSet.permits p call = true :=
  CapSet.covers_sound h hc

/-- `CapSet.attenuate_sound` on the concrete values and limits. -/
theorem concrete_attenuate_sound {parent requested out : CapSet JVal CallsLimit}
    (h : CapSet.attenuate parent requested = .ok out) {call : ToolCall JVal}
    (hc : CapSet.permits out call = true) : CapSet.permits parent call = true :=
  CapSet.attenuate_sound h hc

/-! ## Checks of `hasFloat` on single inputs -/

example : hasFloat 9007199254740992 = true := by decide
example : hasFloat 9007199254740993 = false := by decide
example : hasFloat 1152921504606847000 = true := by decide
example : hasFloat 1152921504606846976 = false := by decide
example : hasFloat 10000000000000000 = true := by decide

end Attenuo
