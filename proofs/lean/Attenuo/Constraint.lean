/-
Argument constraints: `ArgConstraint`, `satisfied_by`, `is_empty` and `implies` in
`crates/attenuo-core/src/capability.rs`.
-/
import Attenuo.Value

namespace Attenuo

open JsonValue

/-- Rust's `i64::MIN` and `i64::MAX`, the bounds of a `range` that omits one. -/
def i64Min : Int := -9223372036854775808
def i64Max : Int := 9223372036854775807

/-- `ArgConstraint`: the five kinds a capability can put on one argument. -/
inductive Constraint (V : Type) where
  /-- `equals`: canonically equal to this value. -/
  | equals (a : V)
  /-- `one_of`: canonically equal to one of these values. -/
  | oneOf (as : List V)
  /-- `prefix`: a string starting with this string. -/
  | strPrefix (p : Str)
  /-- `path_prefix`: a plain path at or below this path. -/
  | pathPrefix (p : Str)
  /-- `range`: an integer between the bounds, inclusive; a missing bound is unbounded. -/
  | range (min max : Option Int)

namespace Constraint

variable {V : Type} [JsonValue V]

/-- A range's lower bound, a missing one as `i64::MIN` (Rust's `bounds`). -/
def lo (min : Option Int) : Int := min.getD i64Min
/-- A range's upper bound, a missing one as `i64::MAX` (Rust's `bounds`). -/
def hi (max : Option Int) : Int := max.getD i64Max

/-- Does the string value start with `p`? (`value.as_str().map(|s| s.starts_with(p))`.) -/
def strStarts (v : V) (p : Str) : Bool :=
  match asStr v with
  | some s => p.isPrefixOf s
  | none => false

/-- `ArgConstraint::satisfied_by`. -/
def sat : Constraint V → V → Bool
  | .equals e, v => veq v e
  | .oneOf os, v => os.any (fun o => veq o v)
  | .strPrefix p, v => strStarts v p
  | .pathPrefix b, v =>
    match asStr v with
    | some s => pathStrWithin b s
    | none => false
  | .range mn mx, v =>
    match asLong v with
    | some n => decide (lo mn ≤ n ∧ n ≤ hi mx)
    | none => false

/-- `ArgConstraint::is_empty`: no value satisfies it. -/
def isEmpty : Constraint V → Bool
  | .oneOf os => os.isEmpty
  | .range mn mx => decide (lo mn > hi mx)
  | .pathPrefix p => (parsePath p).isNone
  | _ => false

/-- `ArgConstraint::implies`, case by case as in the Rust `match`. -/
def implies (c d : Constraint V) : Bool :=
  if c.isEmpty then true
  else match c, d with
  | .equals a, .equals b => veq a b
  | .equals a, .oneOf bs => bs.any (fun b => veq a b)
  | .equals a, .strPrefix p => strStarts a p
  | .oneOf as, .equals b => as.all (fun a => veq a b)
  | .oneOf as, .oneOf bs => as.all (fun a => bs.any (fun b => veq a b))
  | .oneOf as, .strPrefix p => as.all (fun a => strStarts a p)
  | .strPrefix p, .strPrefix q => q.isPrefixOf p
  | .equals a, .pathPrefix b => sat (.pathPrefix b) a
  | .oneOf as, .pathPrefix b => as.all (fun a => sat (.pathPrefix b) a)
  | .pathPrefix q, .pathPrefix b => sat (.pathPrefix b) (ofStr q : V)
  | .pathPrefix q, .strPrefix p => p.isPrefixOf q
  | .strPrefix _, .pathPrefix _ => false
  | .strPrefix _, .equals _ => false
  | .strPrefix _, .oneOf _ => false
  | .pathPrefix _, .equals _ => false
  | .pathPrefix _, .oneOf _ => false
  | .equals a, .range mn mx => admitsAllEqual (lo mn) (hi mx) a
  | .oneOf as, .range mn mx => as.all (fun a => admitsAllEqual (lo mn) (hi mx) a)
  | .range a b, .range c d => decide (lo c ≤ lo a ∧ hi b ≤ hi d)
  | .range a b, .equals e => decide (lo a = hi b) && sat (.equals e) (ofLong (lo a))
  | .range a b, .oneOf es => decide (lo a = hi b) && sat (.oneOf es) (ofLong (lo a))
  | .strPrefix _, .range _ _ => false
  | .pathPrefix _, .range _ _ => false
  | .range _ _, .strPrefix _ => false
  | .range _ _, .pathPrefix _ => false

/-! ## Basic facts -/

theorem veq_symm_iff {a b : V} : veq a b = true ↔ veq b a = true :=
  ⟨veq_symm, veq_symm⟩

/-- An empty constraint admits nothing. -/
theorem not_sat_of_isEmpty {c : Constraint V} (h : c.isEmpty = true) (v : V) :
    c.sat v = false := by
  cases c with
  | equals => simp [isEmpty] at h
  | strPrefix => simp [isEmpty] at h
  | oneOf os => simp_all [isEmpty, sat]
  | pathPrefix p =>
    simp only [isEmpty, Option.isNone_iff_eq_none] at h
    simp only [sat]
    split
    · simp [pathStrWithin, h]
    · rfl
  | range mn mx =>
    simp only [isEmpty, decide_eq_true_eq] at h
    simp only [sat]
    split
    · simp only [decide_eq_false_iff_not]
      omega
    · rfl

/-- Satisfaction of every kind but `range` depends only on the canonical form. -/
def notRange : Constraint V → Bool
  | .range _ _ => false
  | _ => true

theorem sat_congr {d : Constraint V} (hd : d.notRange = true) {a v : V}
    (hva : veq v a = true) (ha : d.sat a = true) : d.sat v = true := by
  have hs := asStr_congr hva
  cases d with
  | equals e => exact veq_trans hva ha
  | oneOf os =>
    simp only [sat, List.any_eq_true] at ha ⊢
    obtain ⟨o, ho, hoa⟩ := ha
    exact ⟨o, ho, veq_trans hoa (veq_symm hva)⟩
  | strPrefix p => simp only [sat, strStarts, hs] at ha ⊢; exact ha
  | pathPrefix b => simp only [sat, hs] at ha ⊢; exact ha
  | range => simp [notRange] at hd

/-! ## Soundness of `implies` -/

/-- **Soundness of `implies`**: if `c` implies `d`, every value satisfying `c` satisfies `d`. -/
theorem implies_sound {c d : Constraint V} (h : implies c d = true) {v : V}
    (hc : c.sat v = true) : d.sat v = true := by
  by_cases he : c.isEmpty = true
  · rw [not_sat_of_isEmpty he] at hc; exact absurd hc (by simp)
  have he' : c.isEmpty = false := by simpa using he
  unfold implies at h
  rw [he'] at h
  simp only [Bool.false_eq_true, ite_false] at h
  cases c with
  | equals a =>
    simp only [sat] at hc
    cases d with
    | equals b => exact veq_trans hc h
    | oneOf bs =>
      simp only [List.any_eq_true] at h
      obtain ⟨b, hb, hab⟩ := h
      simp only [sat, List.any_eq_true]
      exact ⟨b, hb, veq_symm (veq_trans hc hab)⟩
    | strPrefix p => exact sat_congr rfl hc h
    | pathPrefix b => exact sat_congr rfl hc h
    | range mn mx =>
      obtain ⟨n, hn, h1, h2⟩ := (admitsAllEqual_iff _ _ a).mp h v hc
      simp [sat, hn, h1, h2]
  | oneOf as =>
    simp only [sat, List.any_eq_true] at hc
    obtain ⟨a, ha, hav⟩ := hc
    cases d with
    | equals b =>
      simp only [List.all_eq_true] at h
      exact veq_trans (veq_symm hav) (h a ha)
    | oneOf bs =>
      simp only [List.all_eq_true, List.any_eq_true] at h
      obtain ⟨b, hb, hab⟩ := h a ha
      simp only [sat, List.any_eq_true]
      exact ⟨b, hb, veq_trans (veq_symm hab) hav⟩
    | strPrefix p =>
      simp only [List.all_eq_true] at h
      exact sat_congr (d := .strPrefix p) rfl (veq_symm hav) (h a ha)
    | pathPrefix b =>
      simp only [List.all_eq_true] at h
      exact sat_congr (d := .pathPrefix b) rfl (veq_symm hav) (h a ha)
    | range mn mx =>
      simp only [List.all_eq_true] at h
      obtain ⟨n, hn, h1, h2⟩ := (admitsAllEqual_iff _ _ a).mp (h a ha) v (veq_symm hav)
      simp [sat, hn, h1, h2]
  | strPrefix p =>
    cases d with
    | strPrefix q =>
      simp only [sat, strStarts] at hc ⊢
      split at hc
      · next s hs =>
        dsimp only at h
        rw [List.isPrefixOf_iff_prefix] at h hc ⊢
        exact h.trans hc
      · simp at hc
    | _ => simp at h
  | pathPrefix q =>
    cases d with
    | pathPrefix b =>
      simp only [sat, asStr_ofStr] at h hc ⊢
      split at hc
      · next s hs => exact pathStrWithin_trans h hc
      · simp at hc
    | strPrefix p =>
      simp only [sat, strStarts] at hc ⊢
      split at hc
      · next s hs =>
        dsimp only at h
        rw [List.isPrefixOf_iff_prefix] at h ⊢
        exact h.trans (prefix_of_pathStrWithin hc)
      · simp at hc
    | _ => simp at h
  | range mn mx =>
    simp only [sat] at hc
    split at hc
    · next n hn =>
      simp only [decide_eq_true_eq] at hc
      cases d with
      | range c d =>
        simp only [decide_eq_true_eq] at h
        simp only [sat, hn, decide_eq_true_eq]
        omega
      | equals e =>
        simp only [Bool.and_eq_true, decide_eq_true_eq] at h
        have hn' : n = lo mn := by omega
        subst hn'
        exact sat_congr rfl (veq_ofLong hn) h.2
      | oneOf es =>
        simp only [Bool.and_eq_true, decide_eq_true_eq] at h
        have hn' : n = lo mn := by omega
        subst hn'
        exact sat_congr rfl (veq_ofLong hn) h.2
      | _ => simp at h
    · simp at hc

/-! ## Reflexivity and transitivity of `implies` -/

theorem implies_refl (c : Constraint V) : implies c c = true := by
  unfold implies
  split
  · rfl
  · next he =>
    cases c with
    | equals a => exact veq_refl a
    | oneOf as =>
      simp only [List.all_eq_true, List.any_eq_true]
      exact fun a ha => ⟨a, ha, veq_refl a⟩
    | strPrefix p => simp [List.isPrefixOf_iff_prefix]
    | pathPrefix q =>
      simp only [isEmpty, Option.isNone_iff_eq_none] at he
      simp only [sat, asStr_ofStr]
      apply pathStrWithin_refl
      cases h : parsePath q
      · simp_all
      · rfl
    | range mn mx => simp

/-- What `implies (.equals a) d` computes: the strong form of "`a` satisfies `d`", that every
value canonically equal to `a` does. -/
def ssat (d : Constraint V) (a : V) : Bool := implies (.equals a) d

theorem ssat_iff_sat {d : Constraint V} (hd : d.notRange = true) (a : V) :
    ssat d a = d.sat a := by
  cases d with
  | equals b => simp [ssat, implies, sat, isEmpty]
  | oneOf bs =>
    simp only [ssat, implies, isEmpty, Bool.false_eq_true, ite_false, sat]
    apply Bool.eq_iff_iff.mpr
    simp only [List.any_eq_true]
    constructor <;> rintro ⟨b, hb, h⟩ <;> exact ⟨b, hb, veq_symm h⟩
  | strPrefix p => simp [ssat, implies, sat, isEmpty]
  | pathPrefix b => simp [ssat, implies, isEmpty]
  | range => simp [notRange] at hd

theorem ssat_range_iff (mn mx : Option Int) (a : V) :
    ssat (.range mn mx) a = true ↔
      ∀ v, veq v a = true → ∃ n, asLong v = some n ∧ lo mn ≤ n ∧ n ≤ hi mx := by
  simp only [ssat, implies, isEmpty, Bool.false_eq_true, ite_false]
  exact admitsAllEqual_iff _ _ a

/-- `ssat` depends only on the canonical form. -/
theorem ssat_congr {d : Constraint V} {a v : V} (hva : veq v a = true)
    (ha : ssat d a = true) : ssat d v = true := by
  cases d with
  | range mn mx =>
    rw [ssat_range_iff] at ha ⊢
    exact fun w hw => ha w (veq_trans hw hva)
  | _ =>
    rw [ssat_iff_sat rfl] at ha ⊢
    exact sat_congr rfl hva ha

/-- The strong form of soundness: `implies` carries `ssat` along. -/
theorem implies_ssat {b c : Constraint V} (h : implies b c = true) {x : V}
    (hx : ssat b x = true) : ssat c x = true := by
  -- `x` satisfies `b`, so `b` is not empty.
  have hbx : b.sat x = true := by
    cases b with
    | range mn mx =>
      rw [ssat_range_iff] at hx
      obtain ⟨n, hn, h1, h2⟩ := hx x (veq_refl x)
      simp [sat, hn, h1, h2]
    | _ => rwa [ssat_iff_sat rfl] at hx
  have hbe : b.isEmpty = false := by
    cases hb : b.isEmpty
    · rfl
    · rw [not_sat_of_isEmpty hb] at hbx; exact absurd hbx (by simp)
  cases b with
  | equals y =>
    -- `implies (.equals y) c` is `ssat c y`, and `x` is canonically equal to `y`.
    exact ssat_congr hbx h
  | oneOf ys =>
    simp only [sat, List.any_eq_true] at hbx
    obtain ⟨y, hy, hyx⟩ := hbx
    have hc : ssat c y = true := by
      unfold implies at h
      rw [hbe] at h
      simp only [Bool.false_eq_true, ite_false] at h
      cases c with
      | equals e =>
        simp only [List.all_eq_true] at h
        simp [ssat, implies, isEmpty, h y hy]
      | oneOf es =>
        simp only [List.all_eq_true] at h
        simp only [ssat, implies, isEmpty, Bool.false_eq_true, ite_false]
        exact h y hy
      | strPrefix p =>
        simp only [List.all_eq_true] at h
        simp only [ssat, implies, isEmpty, Bool.false_eq_true, ite_false]
        exact h y hy
      | pathPrefix q =>
        simp only [List.all_eq_true] at h
        simp only [ssat, implies, isEmpty, Bool.false_eq_true, ite_false]
        exact h y hy
      | range mn mx =>
        simp only [List.all_eq_true] at h
        simp only [ssat, implies, isEmpty, Bool.false_eq_true, ite_false]
        exact h y hy
    exact ssat_congr (veq_symm hyx) hc
  | strPrefix p =>
    rw [ssat_iff_sat (d := c) ?_]
    · exact implies_sound h hbx
    · cases c <;> simp_all [implies, isEmpty, notRange]
  | pathPrefix q =>
    rw [ssat_iff_sat (d := c) ?_]
    · exact implies_sound h hbx
    · cases c <;> simp_all [implies, isEmpty, notRange]
  | range mn mx =>
    rw [ssat_range_iff] at hx
    obtain ⟨n, hn, h1, h2⟩ := hx x (veq_refl x)
    unfold implies at h
    rw [hbe] at h
    simp only [Bool.false_eq_true, ite_false] at h
    cases c with
    | range c d =>
      rw [ssat_range_iff]
      simp only [decide_eq_true_eq] at h
      intro w hw
      obtain ⟨m, hm, h3, h4⟩ := hx w hw
      exact ⟨m, hm, by omega, by omega⟩
    | equals e =>
      simp only [Bool.and_eq_true, decide_eq_true_eq] at h
      have hn' : n = lo mn := by omega
      subst hn'
      rw [ssat_iff_sat rfl]
      exact sat_congr rfl (veq_ofLong hn) h.2
    | oneOf es =>
      simp only [Bool.and_eq_true, decide_eq_true_eq] at h
      have hn' : n = lo mn := by omega
      subst hn'
      rw [ssat_iff_sat rfl]
      exact sat_congr rfl (veq_ofLong hn) h.2
    | _ => simp at h

/-- **Transitivity of `implies`**. -/
theorem implies_trans {a b c : Constraint V} (hab : implies a b = true)
    (hbc : implies b c = true) : implies a c = true := by
  by_cases hae : a.isEmpty = true
  · simp [implies, hae]
  have hae' : a.isEmpty = false := by simpa using hae
  cases a with
  | equals x =>
    exact implies_ssat (x := x) hbc hab
  | oneOf xs =>
    have hab' := hab
    unfold implies at hab' ⊢
    rw [hae'] at hab' ⊢
    simp only [Bool.false_eq_true, ite_false] at hab' ⊢
    -- Each member `x` has `ssat b x`, so `ssat c x`; that is what `implies` checks.
    have key : ∀ x ∈ xs, ssat c x = true := by
      intro x hx
      apply implies_ssat hbc
      cases b with
      | equals e => simp only [List.all_eq_true] at hab'; simp [ssat, implies, isEmpty, hab' x hx]
      | oneOf es =>
        simp only [List.all_eq_true] at hab'
        simp only [ssat, implies, isEmpty, Bool.false_eq_true, ite_false]; exact hab' x hx
      | strPrefix p =>
        simp only [List.all_eq_true] at hab'
        simp only [ssat, implies, isEmpty, Bool.false_eq_true, ite_false]; exact hab' x hx
      | pathPrefix q =>
        simp only [List.all_eq_true] at hab'
        simp only [ssat, implies, isEmpty, Bool.false_eq_true, ite_false]; exact hab' x hx
      | range mn mx =>
        simp only [List.all_eq_true] at hab'
        simp only [ssat, implies, isEmpty, Bool.false_eq_true, ite_false]; exact hab' x hx
    cases c with
    | equals e =>
      simp only [List.all_eq_true]
      intro x hx; have := key x hx; simpa [ssat, implies, isEmpty] using this
    | oneOf es =>
      simp only [List.all_eq_true]
      intro x hx; have := key x hx; simpa [ssat, implies, isEmpty] using this
    | strPrefix p =>
      simp only [List.all_eq_true]
      intro x hx; have := key x hx; simpa [ssat, implies, isEmpty] using this
    | pathPrefix q =>
      simp only [List.all_eq_true]
      intro x hx; have := key x hx; simpa [ssat, implies, isEmpty] using this
    | range mn mx =>
      simp only [List.all_eq_true]
      intro x hx; have := key x hx; simpa [ssat, implies, isEmpty] using this
  | strPrefix p =>
    unfold implies at hab hbc ⊢
    simp only [isEmpty, Bool.false_eq_true, ite_false] at hab hbc ⊢
    cases b with
    | strPrefix q =>
      cases c with
      | strPrefix r =>
        simp only [Bool.false_eq_true, ite_false, List.isPrefixOf_iff_prefix]
          at hab hbc ⊢
        exact hbc.trans hab
      | _ => simp_all
    | _ => simp_all
  | pathPrefix q =>
    have hq : (parsePath q).isSome := by
      simpa [isEmpty, Option.isNone_iff_eq_none, Option.isSome_iff_ne_none] using hae'
    unfold implies at hab ⊢
    rw [hae'] at hab ⊢
    simp only [Bool.false_eq_true, ite_false] at hab ⊢
    cases b with
    | pathPrefix r =>
      simp only [sat, asStr_ofStr] at hab
      have hre : (Constraint.pathPrefix r : Constraint V).isEmpty = false := by
        cases h : parsePath r
        · simp [pathStrWithin, h] at hab
        · simp [isEmpty, h]
      unfold implies at hbc
      rw [hre] at hbc
      simp only [Bool.false_eq_true, ite_false] at hbc
      cases c with
      | pathPrefix t =>
        simp only [sat, asStr_ofStr] at hbc ⊢
        exact pathStrWithin_trans hbc hab
      | strPrefix p =>
        simp only [List.isPrefixOf_iff_prefix] at hbc ⊢
        exact hbc.trans (prefix_of_pathStrWithin hab)
      | _ => simp_all
    | strPrefix p =>
      unfold implies at hbc
      simp only [isEmpty, Bool.false_eq_true, ite_false] at hbc
      cases c with
      | strPrefix r =>
        simp only [List.isPrefixOf_iff_prefix] at hab hbc ⊢
        exact hbc.trans hab
      | _ => simp_all
    | _ => simp_all
  | range mn mx =>
    have hle : lo mn ≤ hi mx := by
      simp only [isEmpty, decide_eq_false_iff_not] at hae'; omega
    unfold implies at hab ⊢
    rw [hae'] at hab ⊢
    simp only [Bool.false_eq_true, ite_false] at hab ⊢
    cases b with
    | range c' d' =>
      simp only [decide_eq_true_eq] at hab
      have hbe : (Constraint.range c' d' : Constraint V).isEmpty = false := by
        simp only [isEmpty, decide_eq_false_iff_not]; omega
      unfold implies at hbc
      rw [hbe] at hbc
      simp only [Bool.false_eq_true, ite_false] at hbc
      cases c with
      | range c d =>
        simp only [decide_eq_true_eq] at hbc ⊢; omega
      | equals e =>
        simp only [Bool.and_eq_true, decide_eq_true_eq] at hbc ⊢
        have h1 : lo mn = hi mx := by omega
        have h2 : lo mn = lo c' := by omega
        exact ⟨h1, h2 ▸ hbc.2⟩
      | oneOf es =>
        simp only [Bool.and_eq_true, decide_eq_true_eq] at hbc ⊢
        have h1 : lo mn = hi mx := by omega
        have h2 : lo mn = lo c' := by omega
        exact ⟨h1, h2 ▸ hbc.2⟩
      | _ => simp_all
    | equals e =>
      simp only [Bool.and_eq_true, decide_eq_true_eq] at hab
      obtain ⟨hlh, hs⟩ := hab
      -- The single integer `lo mn` satisfies `e`, so it strongly satisfies `c`.
      have hx : ssat (.equals e) (ofLong (V := V) (lo mn)) = true := by
        rw [ssat_iff_sat rfl]; exact hs
      have hc := implies_ssat hbc hx
      cases c with
      | range c d =>
        rw [ssat_range_iff] at hc
        obtain ⟨n, hn, h1, h2⟩ := hc _ (veq_refl _)
        rw [asLong_ofLong] at hn
        simp only [Option.some.injEq] at hn
        simp only [decide_eq_true_eq]; omega
      | equals e' =>
        rw [ssat_iff_sat rfl] at hc
        simp only [Bool.and_eq_true, decide_eq_true_eq]; exact ⟨hlh, hc⟩
      | oneOf es =>
        rw [ssat_iff_sat rfl] at hc
        simp only [Bool.and_eq_true, decide_eq_true_eq]; exact ⟨hlh, hc⟩
      | strPrefix p =>
        rw [ssat_iff_sat rfl] at hc
        simp [sat, strStarts, asStr_ofLong] at hc
      | pathPrefix p =>
        rw [ssat_iff_sat rfl] at hc
        simp [sat, asStr_ofLong] at hc
    | oneOf es =>
      simp only [Bool.and_eq_true, decide_eq_true_eq] at hab
      obtain ⟨hlh, hs⟩ := hab
      have hx : ssat (.oneOf es) (ofLong (V := V) (lo mn)) = true := by
        rw [ssat_iff_sat rfl]; exact hs
      have hc := implies_ssat hbc hx
      cases c with
      | range c d =>
        rw [ssat_range_iff] at hc
        obtain ⟨n, hn, h1, h2⟩ := hc _ (veq_refl _)
        rw [asLong_ofLong] at hn
        simp only [Option.some.injEq] at hn
        simp only [decide_eq_true_eq]; omega
      | equals e' =>
        rw [ssat_iff_sat rfl] at hc
        simp only [Bool.and_eq_true, decide_eq_true_eq]; exact ⟨hlh, hc⟩
      | oneOf es' =>
        rw [ssat_iff_sat rfl] at hc
        simp only [Bool.and_eq_true, decide_eq_true_eq]; exact ⟨hlh, hc⟩
      | strPrefix p =>
        rw [ssat_iff_sat rfl] at hc
        simp [sat, strStarts, asStr_ofLong] at hc
      | pathPrefix p =>
        rw [ssat_iff_sat rfl] at hc
        simp [sat, asStr_ofLong] at hc
    | _ => simp_all

end Constraint

end Attenuo
