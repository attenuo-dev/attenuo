/-
Delegation chains: the capability half of `DelegationChain::validate_at` in
`crates/attenuo-core/src/chain.rs`.

`validate_at` checks much more per hop (ids, names, limits, times, leases). The model keeps
only the check this property rests on: every hop after the root holds a non-empty set of
capabilities that its parent hop's set covers.
-/
import Attenuo.Capability

namespace Attenuo

variable {V L : Type} [JsonValue V] [LimitsModel L]

/-- Each hop's capabilities are covered by the previous hop's, and are not empty
(`!parent.capabilities.covers(&hop.capabilities) || hop.capabilities.is_empty()` fails
validation). The list runs from the root hop to the last hop. -/
def linksValid : List (CapSet V L) → Bool
  | [] => true
  | [_] => true
  | parent :: child :: rest =>
    CapSet.covers parent child && !child.isEmpty && linksValid (child :: rest)

/-- The capability check of `validate_at`: at least one hop, and every link valid. -/
def chainValid (hops : List (CapSet V L)) : Prop :=
  hops ≠ [] ∧ linksValid hops = true

/-- In a valid chain, every hop covers every later hop. -/
theorem linksValid_covers_later {hops : List (CapSet V L)} (h : linksValid hops = true) :
    ∀ i j (hi : i < hops.length) (hj : j < hops.length), i ≤ j →
      CapSet.covers hops[i] hops[j] = true ∨ i = j := by
  induction hops with
  | nil => intro i j hi; simp at hi
  | cons p rest ih =>
    intro i j hi hj hij
    cases rest with
    | nil =>
      simp at hi hj
      right; omega
    | cons c rest' =>
      simp only [linksValid, Bool.and_eq_true, Bool.not_eq_true'] at h
      obtain ⟨⟨hpc, _⟩, hrest⟩ := h
      have ih' := ih hrest
      cases i with
      | zero =>
        cases j with
        | zero => right; rfl
        | succ j =>
          left
          simp only [List.getElem_cons_zero, List.getElem_cons_succ]
          cases j with
          | zero => simpa using hpc
          | succ j' =>
            have hj' : j' + 1 < (c :: rest').length := by simp at hj ⊢; omega
            rcases ih' 0 (j' + 1) (by simp) hj' (by omega) with h0 | h0
            · simp only [List.getElem_cons_zero] at h0
              exact CapSet.covers_trans hpc h0
            · omega
      | succ i =>
        cases j with
        | zero => omega
        | succ j =>
          rcases ih' i j (by simp at hi ⊢; omega) (by simp at hj ⊢; omega) (by omega) with h0 | h0
          · left; simpa using h0
          · right; omega

/-- **Delegation never widens authority.** In a valid chain, a call the last hop's
capabilities permit is permitted by every hop's capabilities, the root's included. -/
theorem chain_permits_all {hops : List (CapSet V L)} (h : chainValid hops)
    {call : ToolCall V} (hlast : CapSet.permits (hops.getLast h.1) call = true) :
    ∀ hop ∈ hops, CapSet.permits hop call = true := by
  intro hop hmem
  obtain ⟨i, hi, rfl⟩ := List.getElem_of_mem hmem
  have hn : hops.length - 1 < hops.length := by
    have := List.length_pos_iff.mpr h.1; omega
  have hlast' : hops.getLast h.1 = hops[hops.length - 1] := List.getLast_eq_getElem h.1
  rw [hlast'] at hlast
  rcases linksValid_covers_later h.2 i (hops.length - 1) hi hn (by omega) with hc | heq
  · exact CapSet.covers_sound hc hlast
  · subst heq; exact hlast

/-- The root's capabilities permit every call the last hop's permit. -/
theorem chain_root_permits {hops : List (CapSet V L)} (h : chainValid hops)
    {call : ToolCall V} (hlast : CapSet.permits (hops.getLast h.1) call = true) :
    CapSet.permits (hops.head h.1) call = true :=
  chain_permits_all h hlast _ (List.head_mem h.1)

/-- Extending a valid chain by a hop that `attenuate` produced from the last hop keeps it
valid (what `DelegationChain::extend` does, capability half only). -/
theorem chainValid_extend {hops : List (CapSet V L)} (h : chainValid hops)
    {requested out : CapSet V L}
    (ha : CapSet.attenuate (hops.getLast h.1) requested = .ok out) :
    chainValid (hops ++ [out]) := by
  obtain ⟨hcov, hne⟩ := CapSet.attenuate_covered ha
  refine ⟨by simp, ?_⟩
  obtain ⟨hne0, hv⟩ := h
  -- Induct on the chain, keeping track of the last hop.
  induction hops with
  | nil => exact absurd rfl hne0
  | cons p rest ih =>
    cases rest with
    | nil =>
      simp only [List.getLast_singleton] at hcov
      have : out.isEmpty = false := by simpa [List.isEmpty_iff] using hne
      simp [linksValid, hcov, this]
    | cons c rest' =>
      simp only [linksValid, Bool.and_eq_true, Bool.not_eq_true'] at hv
      have hlast : (p :: c :: rest').getLast hne0 = (c :: rest').getLast (by simp) := by
        simp [List.getLast_cons]
      rw [hlast] at ha hcov
      have := ih (by simp) hv.2 ha hcov
      simp only [List.cons_append, linksValid, Bool.and_eq_true, Bool.not_eq_true'] at this ⊢
      exact ⟨hv.1, this⟩

end Attenuo
