/-
Capabilities and capability sets: `pattern_covers`, `pattern_matches`, `Capability::covers`,
`covers_calls`, `permits`, `CapabilitySet::covers`, `permits`, `attenuate` and
`attenuate_with` in `crates/attenuo-core/src/capability.rs`.
-/
import Attenuo.Constraint

namespace Attenuo

open JsonValue

/-! ## Name patterns -/

/-- `s.strip_suffix('*')`. -/
def stripStar (s : Str) : Option Str :=
  if s.getLast? = some '*' then some s.dropLast else none

/-- Rust's `pattern_matches`: `*` matches anything, `prefix*` matches names starting with
`prefix`, anything else matches only itself. -/
def patternMatches (pat name : Str) : Bool :=
  if pat = ['*'] then true
  else match stripStar pat with
    | some p => p.isPrefixOf name
    | none => decide (pat = name)

/-- Rust's `pattern_covers`: does the pattern `parent` match every name `child` matches? -/
def patternCovers (parent child : Str) : Bool :=
  if parent = ['*'] then true
  else match stripStar parent, stripStar child with
    | some p, some c => p.isPrefixOf c
    | some p, none => p.isPrefixOf child
    | none, some _ => false
    | none, none => decide (parent = child)

theorem stripStar_eq {s p : Str} (h : stripStar s = some p) : s = p ++ ['*'] := by
  unfold stripStar at h
  split at h
  · next hl =>
    simp only [Option.some.injEq] at h
    obtain ⟨u, rfl⟩ := List.getLast?_eq_some_iff.mp hl
    simp_all
  · simp at h

theorem stripStar_snoc (p : Str) : stripStar (p ++ ['*']) = some p := by
  simp [stripStar]

theorem stripStar_none_ne {s p : Str} (h : stripStar s = none) : s ≠ p ++ ['*'] := by
  rintro rfl
  simp [stripStar_snoc] at h

theorem patternMatches_star (n : Str) : patternMatches ['*'] n = true := by
  simp [patternMatches]

/-- `prefix*` matches what `prefix` starts, also when the pattern is `*` itself. -/
theorem patternMatches_glob {p n : Str} :
    patternMatches (p ++ ['*']) n = p.isPrefixOf n := by
  unfold patternMatches
  split
  · next h =>
    have : p = [] := by
      cases p with
      | nil => rfl
      | cons x xs => simp at h
    subst this; simp
  · rw [stripStar_snoc]

theorem patternMatches_exact {s n : Str} (h : stripStar s = none) :
    patternMatches s n = decide (s = n) := by
  unfold patternMatches
  split
  · next hs => subst hs; simp [stripStar] at h
  · rw [h]

/-- **Soundness of `pattern_covers`**. -/
theorem patternCovers_sound {p c n : Str} (h : patternCovers p c = true)
    (hc : patternMatches c n = true) : patternMatches p n = true := by
  unfold patternCovers at h
  split at h
  · next hp => subst hp; exact patternMatches_star n
  · next hp =>
    cases hsp : stripStar p with
    | none =>
      cases hsc : stripStar c with
      | none =>
        simp only [hsp, hsc, decide_eq_true_eq] at h
        subst h
        exact hc
      | some _ => simp [hsp, hsc] at h
    | some p' =>
      rw [stripStar_eq hsp, patternMatches_glob, List.isPrefixOf_iff_prefix]
      cases hsc : stripStar c with
      | none =>
        simp only [hsp, hsc, List.isPrefixOf_iff_prefix] at h
        rw [patternMatches_exact hsc, decide_eq_true_eq] at hc
        subst hc
        exact h
      | some c' =>
        simp only [hsp, hsc, List.isPrefixOf_iff_prefix] at h
        rw [stripStar_eq hsc, patternMatches_glob, List.isPrefixOf_iff_prefix] at hc
        exact h.trans hc

theorem patternCovers_refl (p : Str) : patternCovers p p = true := by
  unfold patternCovers
  split
  · rfl
  · cases stripStar p <;> simp [List.isPrefixOf_iff_prefix]

theorem patternCovers_glob (p c : Str) :
    patternCovers (p ++ ['*']) c =
      (match stripStar c with
       | some c' => p.isPrefixOf c'
       | none => p.isPrefixOf c) := by
  unfold patternCovers
  split
  · next h =>
    have : p = [] := by
      cases p with
      | nil => rfl
      | cons x xs => simp at h
    subst this
    cases stripStar c <;> simp
  · rw [stripStar_snoc]
    cases stripStar c <;> rfl

theorem patternCovers_exact {s : Str} (hs : stripStar s = none) (c : Str) :
    patternCovers s c = (decide (stripStar c = none) && decide (s = c)) := by
  unfold patternCovers
  split
  · next h => subst h; simp [stripStar] at hs
  · rw [hs]
    cases stripStar c <;> simp

theorem patternCovers_trans {a b c : Str} (hab : patternCovers a b = true)
    (hbc : patternCovers b c = true) : patternCovers a c = true := by
  cases hsa : stripStar a with
  | some a' =>
    rw [stripStar_eq hsa] at hab ⊢
    rw [patternCovers_glob] at hab ⊢
    cases hsb : stripStar b with
    | some b' =>
      rw [hsb] at hab
      rw [stripStar_eq hsb, patternCovers_glob] at hbc
      simp only [List.isPrefixOf_iff_prefix] at hab
      cases hsc : stripStar c with
      | some c' =>
        rw [hsc] at hbc
        simp only [List.isPrefixOf_iff_prefix] at hbc ⊢
        exact hab.trans hbc
      | none =>
        rw [hsc] at hbc
        simp only [List.isPrefixOf_iff_prefix] at hbc ⊢
        exact hab.trans hbc
    | none =>
      rw [hsb] at hab
      rw [patternCovers_exact hsb] at hbc
      simp only [Bool.and_eq_true, decide_eq_true_eq] at hbc
      obtain ⟨hsc, rfl⟩ := hbc
      rw [hsc]
      exact hab
  | none =>
    rw [patternCovers_exact hsa] at hab ⊢
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hab ⊢
    obtain ⟨hsb, rfl⟩ := hab
    rw [patternCovers_exact hsb] at hbc
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hbc
    exact hbc

/-! ## Tool calls and capabilities -/

/-- `ToolCall`: a server, a tool and named arguments. Arguments that are not a JSON object
are modelled as an empty list (Rust's `Value::get` finds nothing in them). `namesOk` stands
for `ToolCall::check_names().is_ok()`, left abstract: the same check runs on both sides of
every theorem, so its details do not matter here. -/
structure ToolCall (V : Type) where
  server : Str
  tool : Str
  args : List (Str × V)
  namesOk : Bool

/-- What the model keeps of `Limits`: a type with `Limits::narrows` and the static clamp
`Limits::clamp_to`. Limits bound how many calls a run may make; they never change which call
a capability permits, so the call half of the proofs does not look inside them. -/
class LimitsModel (L : Type) where
  /-- `child.narrows(parent)`. -/
  narrows : L → L → Bool
  narrows_refl : ∀ l, narrows l l = true
  narrows_trans : ∀ {a b c}, narrows a b = true → narrows b c = true → narrows a c = true
  /-- `requested.clamp_to(parent)`. -/
  clampTo : L → L → L

/-- `Capability`: server and tool patterns, constraints by argument name, and limits. Rust's
`BTreeMap` of constraints is a list of pairs here; lookups take the first entry for a name. -/
structure Capability (V L : Type) where
  server : Str
  tool : Str
  constraints : List (Str × Constraint V)
  limits : L

/-! ## Facts about `lookup` -/

theorem mem_of_lookup {β : Type} {l : List (Str × β)} {k : Str} {b : β}
    (h : l.lookup k = some b) : (k, b) ∈ l := by
  induction l with
  | nil => simp at h
  | cons e es ih =>
    obtain ⟨k', b'⟩ := e
    rw [List.lookup_cons] at h
    by_cases hk : k = k'
    · subst hk
      simp only [beq_self_eq_true, Option.some.injEq] at h
      subst h
      exact List.mem_cons_self
    · have : (k == k') = false := by simpa using hk
      rw [this] at h
      exact List.mem_cons_of_mem _ (ih h)

theorem lookup_of_mem {β : Type} {l : List (Str × β)} (hu : (l.map Prod.fst).Nodup)
    {k : Str} {b : β} (h : (k, b) ∈ l) : l.lookup k = some b := by
  induction l with
  | nil => simp at h
  | cons e es ih =>
    obtain ⟨k', b'⟩ := e
    simp only [List.map_cons, List.nodup_cons, List.mem_map] at hu
    rw [List.lookup_cons]
    rcases List.mem_cons.mp h with he | he
    · simp only [Prod.mk.injEq] at he
      obtain ⟨rfl, rfl⟩ := he
      simp
    · have hk : k ≠ k' := by
        rintro rfl
        exact hu.1 ⟨(k, b), he, rfl⟩
      have : (k == k') = false := by simpa using hk
      rw [this]
      exact ih hu.2 he

/-- The first member, with its index, for which `f` holds (Rust's
`iter().enumerate().find(..)`). -/
def findIndexed {α : Type} (f : α → Bool) : List α → Nat → Option (Nat × α)
  | [], _ => none
  | x :: xs, i => if f x then some (i, x) else findIndexed f xs (i + 1)

theorem findIndexed_mem {α : Type} {f : α → Bool} {l : List α} {i j : Nat} {x : α}
    (h : findIndexed f l i = some (j, x)) : x ∈ l := by
  induction l generalizing i with
  | nil => simp [findIndexed] at h
  | cons y ys ih =>
    unfold findIndexed at h
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      rw [← h.2]; exact List.mem_cons_self
    · exact List.mem_cons_of_mem _ (ih h)

variable {V L : Type} [JsonValue V]

/-- `Capability::permits`. -/
def Capability.permits (cap : Capability V L) (call : ToolCall V) : Bool :=
  call.namesOk
  && patternMatches cap.server call.server
  && patternMatches cap.tool call.tool
  && cap.constraints.all (fun (arg, c) =>
      match call.args.lookup arg with
      | some v => c.sat v
      | none => false)

/-- `Capability::covers_calls`: patterns and constraints, ignoring limits. -/
def Capability.coversCalls (parent child : Capability V L) : Bool :=
  patternCovers parent.server child.server
  && patternCovers parent.tool child.tool
  && parent.constraints.all (fun (arg, pc) =>
      match child.constraints.lookup arg with
      | some cc => cc.implies pc
      | none => false)

/-- **Soundness of `covers_calls`**: a call the child permits, the parent permits. -/
theorem Capability.coversCalls_sound {p c : Capability V L} (h : p.coversCalls c = true)
    {call : ToolCall V} (hc : c.permits call = true) : p.permits call = true := by
  simp only [coversCalls, Bool.and_eq_true, List.all_eq_true] at h
  obtain ⟨⟨hs, ht⟩, hcons⟩ := h
  simp only [permits, Bool.and_eq_true, List.all_eq_true] at hc ⊢
  obtain ⟨⟨⟨hn, hms⟩, hmt⟩, hccons⟩ := hc
  refine ⟨⟨⟨hn, patternCovers_sound hs hms⟩, patternCovers_sound ht hmt⟩, ?_⟩
  intro ⟨arg, pc⟩ hmem
  have himp := hcons ⟨arg, pc⟩ hmem
  simp only at himp ⊢
  cases hlk : c.constraints.lookup arg with
  | none => simp [hlk] at himp
  | some cc =>
    rw [hlk] at himp
    have hmemc : (arg, cc) ∈ c.constraints := mem_of_lookup hlk
    have hsat := hccons (arg, cc) hmemc
    simp only at hsat
    cases hv : call.args.lookup arg with
    | none => simp [hv] at hsat
    | some v =>
      rw [hv] at hsat
      exact Constraint.implies_sound himp hsat

/-- Rust's `BTreeMap` holds one constraint per argument name. -/
def Capability.wellFormed (c : Capability V L) : Prop :=
  (c.constraints.map Prod.fst).Nodup

/-- `covers_calls` is reflexive on capabilities with one constraint per argument. -/
theorem Capability.coversCalls_refl {c : Capability V L} (hw : c.wellFormed) :
    c.coversCalls c = true := by
  simp only [coversCalls, patternCovers_refl, Bool.true_and, List.all_eq_true]
  intro ⟨arg, pc⟩ hmem
  simp only [lookup_of_mem hw hmem]
  exact Constraint.implies_refl pc

theorem Capability.coversCalls_trans {a b c : Capability V L} (hab : a.coversCalls b = true)
    (hbc : b.coversCalls c = true) : a.coversCalls c = true := by
  simp only [coversCalls, Bool.and_eq_true, List.all_eq_true] at hab hbc ⊢
  obtain ⟨⟨hs1, ht1⟩, hc1⟩ := hab
  obtain ⟨⟨hs2, ht2⟩, hc2⟩ := hbc
  refine ⟨⟨patternCovers_trans hs1 hs2, patternCovers_trans ht1 ht2⟩, ?_⟩
  intro ⟨arg, pa⟩ hmem
  have h1 := hc1 ⟨arg, pa⟩ hmem
  simp only at h1 ⊢
  cases hlb : b.constraints.lookup arg with
  | none => simp [hlb] at h1
  | some pb =>
    rw [hlb] at h1
    have h2 := hc2 ⟨arg, pb⟩ (mem_of_lookup hlb)
    simp only at h2
    cases hlc : c.constraints.lookup arg with
    | none => simp [hlc] at h2
    | some pc =>
      rw [hlc] at h2
      exact Constraint.implies_trans h2 h1

variable [LimitsModel L]

/-- `Capability::covers`: the call half, and limits no larger than the parent's. -/
def Capability.covers (parent child : Capability V L) : Bool :=
  parent.coversCalls child && LimitsModel.narrows child.limits parent.limits

/-- **Soundness of `Capability::covers`**. -/
theorem Capability.covers_sound {p c : Capability V L} (h : p.covers c = true)
    {call : ToolCall V} (hc : c.permits call = true) : p.permits call = true := by
  simp only [covers, Bool.and_eq_true] at h
  exact coversCalls_sound h.1 hc

theorem Capability.covers_refl {c : Capability V L} (hw : c.wellFormed) : c.covers c = true := by
  simp [covers, coversCalls_refl hw, LimitsModel.narrows_refl]

theorem Capability.covers_trans {a b c : Capability V L} (hab : a.covers b = true)
    (hbc : b.covers c = true) : a.covers c = true := by
  simp only [covers, Bool.and_eq_true] at hab hbc ⊢
  exact ⟨coversCalls_trans hab.1 hbc.1, LimitsModel.narrows_trans hbc.2 hab.2⟩

/-! ## Capability sets -/

/-- `CapabilitySet`: a call is permitted if any member permits it. Rust's `BTreeSet` is a list
here; order and duplicates change nothing below. -/
abbrev CapSet (V L : Type) := List (Capability V L)

/-- `CapabilitySet::permits`. -/
def CapSet.permits (s : CapSet V L) (call : ToolCall V) : Bool :=
  s.any (fun c => c.permits call)

/-- `CapabilitySet::covers`: each child capability is covered by one parent capability. -/
def CapSet.covers (parent child : CapSet V L) : Bool :=
  child.all (fun c => parent.any (fun p => p.covers c))

/-- **Soundness of `CapabilitySet::covers`**: a call the child set permits, the parent set
permits. -/
theorem CapSet.covers_sound {p c : CapSet V L} (h : CapSet.covers p c = true)
    {call : ToolCall V} (hc : CapSet.permits c call = true) : CapSet.permits p call = true := by
  simp only [CapSet.permits, CapSet.covers, List.any_eq_true, List.all_eq_true] at h hc ⊢
  obtain ⟨cc, hcc, hperm⟩ := hc
  obtain ⟨pc, hpc, hcov⟩ := h cc hcc
  exact ⟨pc, hpc, Capability.covers_sound hcov hperm⟩

theorem CapSet.covers_refl {s : CapSet V L} (hw : ∀ c ∈ s, c.wellFormed) :
    CapSet.covers s s = true := by
  simp only [CapSet.covers, List.all_eq_true, List.any_eq_true]
  exact fun c hc => ⟨c, hc, Capability.covers_refl (hw c hc)⟩

theorem CapSet.covers_trans {a b c : CapSet V L} (hab : CapSet.covers a b = true)
    (hbc : CapSet.covers b c = true) : CapSet.covers a c = true := by
  simp only [CapSet.covers, List.all_eq_true, List.any_eq_true] at hab hbc ⊢
  intro x hx
  obtain ⟨y, hy, hyx⟩ := hbc x hx
  obtain ⟨z, hz, hzy⟩ := hab y hy
  exact ⟨z, hz, Capability.covers_trans hzy hyx⟩

/-! ## Attenuation -/

/-- Why `attenuate` refuses (`AttenuationError`). -/
inductive AttenuationError where
  | empty
  | notCovered
deriving DecidableEq

/-- One requested capability, as `attenuate_with` treats it: find its parent (one that covers
it as it is, else one that covers its calls), let `adjust` produce the child from the parent's
index, the parent and the request, and keep the child only if the parent covers it.
`adjust` stands for the limit clamping (`clamp_to` and the `remaining` lowering): any function
at all, since the final `covers` check is what the theorem rests on. -/
def attenuateOne (adjust : Nat → Capability V L → Capability V L → Capability V L)
    (parent : CapSet V L) (c : Capability V L) : Except AttenuationError (Capability V L) :=
  match (findIndexed (fun p => p.covers c) parent 0).orElse
      (fun _ => findIndexed (fun p => p.coversCalls c) parent 0) with
  | none => .error .notCovered
  | some (i, p) =>
    let child := adjust i p c
    if p.covers child then .ok child else .error .notCovered

/-- The loop of `attenuate_with` over the requested capabilities. -/
def attenuateAll (adjust : Nat → Capability V L → Capability V L → Capability V L)
    (parent : CapSet V L) : CapSet V L → Except AttenuationError (CapSet V L)
  | [] => .ok []
  | c :: cs =>
    match attenuateOne adjust parent c with
    | .error e => .error e
    | .ok child =>
      match attenuateAll adjust parent cs with
      | .error e => .error e
      | .ok rest => .ok (child :: rest)

/-- `CapabilitySet::attenuate_with`. -/
def CapSet.attenuateWith (adjust : Nat → Capability V L → Capability V L → Capability V L)
    (parent requested : CapSet V L) : Except AttenuationError (CapSet V L) :=
  if requested.isEmpty then .error .empty else attenuateAll adjust parent requested

/-- `CapabilitySet::attenuate`: limits clamped to the parent's with nothing spent yet. -/
def CapSet.attenuate (parent requested : CapSet V L) : Except AttenuationError (CapSet V L) :=
  CapSet.attenuateWith
    (fun _ p c => { c with limits := LimitsModel.clampTo c.limits p.limits }) parent requested

theorem attenuateOne_covered {adjust : Nat → Capability V L → Capability V L → Capability V L}
    {parent : CapSet V L} {c child : Capability V L}
    (h : attenuateOne adjust parent c = .ok child) : parent.any (fun p => p.covers child) = true := by
  unfold attenuateOne at h
  split at h
  · simp at h
  · next i p hfind =>
    simp only at h
    split at h
    · next hcov =>
      simp only [Except.ok.injEq] at h
      subst h
      have hmem : p ∈ parent := by
        cases h1 : findIndexed (fun p => p.covers c) parent 0 with
        | none =>
          rw [h1] at hfind
          exact findIndexed_mem hfind
        | some r =>
          rw [h1] at hfind
          simp only [Option.orElse_some, Option.some.injEq] at hfind
          rw [hfind] at h1
          exact findIndexed_mem h1
      exact List.any_eq_true.mpr ⟨p, hmem, hcov⟩
    · simp at h

theorem attenuateAll_covered {adjust : Nat → Capability V L → Capability V L → Capability V L}
    {parent requested out : CapSet V L}
    (h : attenuateAll adjust parent requested = .ok out) :
    CapSet.covers parent out = true ∧ out.length = requested.length := by
  induction requested generalizing out with
  | nil =>
    simp only [attenuateAll, Except.ok.injEq] at h
    subst h; simp [CapSet.covers]
  | cons c cs ih =>
    unfold attenuateAll at h
    split at h
    · simp at h
    · next child hone =>
      split at h
      · simp at h
      · next rest hrest =>
        simp only [Except.ok.injEq] at h
        subst h
        obtain ⟨hcov, hlen⟩ := ih hrest
        refine ⟨?_, by simp [hlen]⟩
        simp only [CapSet.covers, List.all_cons, Bool.and_eq_true] at hcov ⊢
        exact ⟨attenuateOne_covered hone, hcov⟩

/-- **`attenuate_with` only narrows**: whatever the limit adjustment, a successful result is
non-empty and covered by the parent set. -/
theorem CapSet.attenuateWith_covered
    {adjust : Nat → Capability V L → Capability V L → Capability V L}
    {parent requested out : CapSet V L}
    (h : CapSet.attenuateWith adjust parent requested = .ok out) :
    CapSet.covers parent out = true ∧ out ≠ [] := by
  unfold CapSet.attenuateWith at h
  split at h
  · simp at h
  · next hne =>
    obtain ⟨hcov, hlen⟩ := attenuateAll_covered h
    refine ⟨hcov, ?_⟩
    intro hout
    subst hout
    cases requested with
    | nil => simp at hne
    | cons => simp at hlen

/-- **`attenuate` only narrows**. -/
theorem CapSet.attenuate_covered {parent requested out : CapSet V L}
    (h : CapSet.attenuate parent requested = .ok out) :
    CapSet.covers parent out = true ∧ out ≠ [] :=
  CapSet.attenuateWith_covered h

/-- A call the attenuated set permits, the parent set permits. -/
theorem CapSet.attenuate_sound {parent requested out : CapSet V L}
    (h : CapSet.attenuate parent requested = .ok out) {call : ToolCall V}
    (hc : CapSet.permits out call = true) : CapSet.permits parent call = true :=
  CapSet.covers_sound (CapSet.attenuate_covered h).1 hc

end Attenuo
