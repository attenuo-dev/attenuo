/-
JSON values, as far as constraints look at them.

The model does not build JSON or its RFC 8785 canonical form. It takes any type of values
together with the operations constraints use and the facts the proofs need about them. Each
field below names the Rust function it stands for. The facts are not proven about the Rust
code; README.md lists them and why each holds by reading the Rust.
-/
import Attenuo.Path

namespace Attenuo

/-- The operations on JSON values that `ArgConstraint` uses, with the facts the proofs rely
on. A theorem about the model holds for every type with these operations and facts. -/
class JsonValue (V : Type) where
  /-- `jcs::value_eq`: equality of canonical forms (`1` equals `1.0`). -/
  veq : V → V → Bool
  veq_refl : ∀ a, veq a a = true
  veq_symm : ∀ {a b}, veq a b = true → veq b a = true
  veq_trans : ∀ {a b c}, veq a b = true → veq b c = true → veq a c = true
  /-- `Value::as_str`. -/
  asStr : V → Option Str
  /-- Canonically equal values are the same string or both not strings. -/
  asStr_congr : ∀ {a b}, veq a b = true → asStr a = asStr b
  /-- `Value::String`. -/
  ofStr : Str → V
  asStr_ofStr : ∀ s, asStr (ofStr s) = some s
  /-- `as_long`: the value as a Cedar `long`, if it is one. -/
  asLong : V → Option Int
  /-- `Value::from(i64)`. -/
  ofLong : Int → V
  asLong_ofLong : ∀ n, asLong (ofLong n) = some n
  asStr_ofLong : ∀ n, asStr (ofLong n) = none
  /-- A value `as_long` reads as `n` is canonically equal to the integer `n` (`5.0` and `5`). -/
  veq_ofLong : ∀ {v n}, asLong v = some n → veq v (ofLong n) = true
  /-- `range_admits_all_equal`, for the range with these inclusive bounds. -/
  admitsAllEqual : Int → Int → V → Bool
  /-- It holds exactly when every value canonically equal to `a` is an integer in the range. -/
  admitsAllEqual_iff : ∀ lo hi a, admitsAllEqual lo hi a = true ↔
    ∀ v, veq v a = true → ∃ n, asLong v = some n ∧ lo ≤ n ∧ n ≤ hi

/-! ## A small instance

The facts above can all hold at once: here is a type of values that has them. It shows the
theorems are not vacuous. -/

/-- A toy JSON value: a string, an integer, or anything else. -/
inductive ToyValue where
  | str (s : Str)
  | int (n : Int)
  | other (k : Nat)
deriving DecidableEq

instance : JsonValue ToyValue where
  veq a b := decide (a = b)
  veq_refl a := by simp
  veq_symm h := by simp_all
  veq_trans h1 h2 := by simp_all
  asStr | .str s => some s | _ => none
  asStr_congr h := by simp_all
  ofStr := .str
  asStr_ofStr _ := rfl
  asLong | .int n => some n | _ => none
  ofLong := .int
  asLong_ofLong _ := rfl
  asStr_ofLong _ := rfl
  veq_ofLong {v n} h := by
    cases v <;> simp_all
  admitsAllEqual lo hi
    | .int n => decide (lo ≤ n ∧ n ≤ hi)
    | _ => false
  admitsAllEqual_iff lo hi a := by
    cases a <;> simp

end Attenuo
