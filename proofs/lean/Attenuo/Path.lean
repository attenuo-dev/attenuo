/-
Paths as `path_prefix` reads them: `parse_path`, `path_within` and `path_str_within` in
`crates/attenuo-core/src/capability.rs`.

Strings are modelled as lists of Unicode scalar values (`List Char`). Rust works on UTF-8
bytes for the percent checks; every byte those checks look for is ASCII, and an ASCII byte in
UTF-8 is always a whole character, so checking characters gives the same answer.
-/

namespace Attenuo

/-- A string, as a list of characters. -/
abbrev Str := List Char

/-! ## Splitting and joining on `/` -/

/-- Split on every `/`, like Rust's `str::split('/')`: `"a/b"` gives `["a", "b"]`, `""` gives
`[""]`. Never returns the empty list. -/
def splitSlash : Str → List Str
  | [] => [[]]
  | c :: cs =>
    if c = '/' then [] :: splitSlash cs
    else match splitSlash cs with
      | [] => [[c]]
      | g :: gs => (c :: g) :: gs

/-- `/` followed by each segment, joined: the tail of a `/`-joined list. -/
def sepJoin : List Str → Str
  | [] => []
  | g :: gs => '/' :: (g ++ sepJoin gs)

/-- Segments joined with `/` between them (Rust's `segments.join("/")`). -/
def joinSlash : List Str → Str
  | [] => []
  | g :: gs => g ++ sepJoin gs

theorem splitSlash_ne_nil (l : Str) : splitSlash l ≠ [] := by
  cases l with
  | nil => simp [splitSlash]
  | cons c cs =>
    unfold splitSlash
    split
    · simp
    · split <;> simp

theorem joinSlash_cons_cons (g h : Str) (hs : List Str) :
    joinSlash (g :: h :: hs) = g ++ '/' :: joinSlash (h :: hs) := by
  simp [joinSlash, sepJoin]

theorem joinSlash_splitSlash (l : Str) : joinSlash (splitSlash l) = l := by
  induction l with
  | nil => simp [splitSlash, joinSlash, sepJoin]
  | cons c cs ih =>
    unfold splitSlash
    by_cases hc : c = '/'
    · simp only [hc, ite_true]
      have hne := splitSlash_ne_nil cs
      cases hs : splitSlash cs with
      | nil => exact absurd hs hne
      | cons h t =>
        rw [hs] at ih
        rw [joinSlash_cons_cons, ih]
        simp
    · simp only [hc, ite_false]
      cases hs : splitSlash cs with
      | nil => exact absurd hs (splitSlash_ne_nil cs)
      | cons h t =>
        rw [hs] at ih
        simp only [joinSlash] at ih ⊢
        simp [ih]

theorem sepJoin_append (a b : List Str) : sepJoin (a ++ b) = sepJoin a ++ sepJoin b := by
  induction a with
  | nil => simp [sepJoin]
  | cons g gs ih => simp [sepJoin, ih]

theorem joinSlash_append {a b : List Str} (ha : a ≠ []) (hb : b ≠ []) :
    joinSlash (a ++ b) = joinSlash a ++ '/' :: joinSlash b := by
  cases a with
  | nil => exact absurd rfl ha
  | cons g gs =>
    cases b with
    | nil => exact absurd rfl hb
    | cons h hs =>
      simp [joinSlash, sepJoin_append, sepJoin]

/-! ## The checks `parse_path` makes before it splits -/

/-- Rust's `char::is_control`: general category Cc (U+0000 to U+001F and U+007F to U+009F). -/
def isControl (c : Char) : Bool :=
  c.toNat < 0x20 || (0x7f ≤ c.toNat && c.toNat ≤ 0x9f)

/-- An ASCII hex digit. -/
def isHexDigit (c : Char) : Bool :=
  ('0' ≤ c && c ≤ '9') || ('a' ≤ c && c ≤ 'f') || ('A' ≤ c && c ≤ 'F')

/-- ASCII lower case of one character. -/
def asciiLower (c : Char) : Char :=
  if 'A' ≤ c && c ≤ 'Z' then Char.ofNat (c.toNat + 32) else c

/-- `%2e`, `%2f` or `%5c` in either case somewhere in the string. -/
def hasEncodedSeparator : Str → Bool
  | a :: b :: c :: rest =>
    (a == '%' &&
      ((b == '2' && (asciiLower c == 'e' || asciiLower c == 'f')) ||
       (b == '5' && asciiLower c == 'c')))
    || hasEncodedSeparator (b :: c :: rest)
  | _ => false

/-- `%25` followed by two hex digits somewhere in the string. -/
def hasDoubleEncoded : Str → Bool
  | a :: b :: c :: d :: e :: rest =>
    (a == '%' && b == '2' && c == '5' && isHexDigit d && isHexDigit e)
    || hasDoubleEncoded (b :: c :: d :: e :: rest)
  | _ => false

/-- `LOOKALIKE_SEPARATORS`: code points that NFKC or Windows best-fit conversion turns into
`.`, `/` or `\`. -/
def lookalikeSeparators : List Char :=
  ['․', '‥', '…', '︙', '︰', '﹒', '﹨', '．',
   '／', '＼', '⁄', '∕', '⧸']

/-- Two `/` in a row somewhere in the string (an empty segment). -/
def hasDoubleSlash : Str → Bool
  | a :: b :: rest => (a == '/' && b == '/') || hasDoubleSlash (b :: rest)
  | _ => false

/-- Every refusal `parse_path` makes before splitting, in its order: empty, backslash,
control character, percent-encoded separator, double-encoded escape, lookalike separator,
empty segment. -/
def refused (s : Str) : Bool :=
  s.isEmpty
  || s.contains '\\'
  || s.any isControl
  || hasEncodedSeparator s
  || hasDoubleEncoded s
  || s.any (fun c => lookalikeSeparators.contains c)
  || hasDoubleSlash s

/-! ## Parsing -/

/-- Rust's `PathSegments`: whether the path starts with `/`, its segments, and whether it ends
with `/`. -/
structure PathSegs where
  absolute : Bool
  segs : List Str
  dir : Bool
deriving DecidableEq, Repr

/-- `body.strip_suffix('/').unwrap_or(body)`. -/
def stripLastSlash (b : Str) : Str :=
  if b.getLast? = some '/' then b.dropLast else b

/-- A segment that is `.` or `..`. -/
def isDotSegment (g : Str) : Bool :=
  g == ['.'] || g == ['.', '.']

/-- Does the string start with `/`? -/
def isAbsolute (s : Str) : Bool := decide (s.head? = some '/')

/-- Does the string end with `/`? -/
def endsWithSlash (s : Str) : Bool := decide (s.getLast? = some '/')

/-- The string without its leading `/` (when absolute) and without one trailing `/`. -/
def bodyOf (s : Str) : Str :=
  stripLastSlash (if isAbsolute s then s.tail else s)

/-- The segments of the body: none for an empty body, else the body split on `/`. -/
def segsOf (s : Str) : List Str :=
  if bodyOf s = [] then [] else splitSlash (bodyOf s)

/-- Rust's `parse_path`: `none` when the string is not a plain path. -/
def parsePath (s : Str) : Option PathSegs :=
  if refused s then none
  else if (segsOf s).any isDotSegment then none
  else some { absolute := isAbsolute s, segs := segsOf s, dir := endsWithSlash s }

theorem parsePath_eq {s : Str} {p : PathSegs} (h : parsePath s = some p) :
    refused s = false ∧
    p = { absolute := isAbsolute s, segs := segsOf s, dir := endsWithSlash s } := by
  unfold parsePath at h
  cases hr : refused s
  · cases hd : (segsOf s).any isDotSegment
    · simp only [hr, hd, Bool.false_eq_true, ite_false, Option.some.injEq] at h
      exact ⟨rfl, h.symm⟩
    · simp [hr, hd] at h
  · simp [hr] at h

/-- Rust's `path_within`: is the path `v` at or below the path `b`? -/
def within (b v : PathSegs) : Bool :=
  b.absolute == v.absolute
  && b.segs.isPrefixOf v.segs
  && (!b.dir || v.dir || decide (v.segs.length > b.segs.length))

/-- Rust's `path_str_within`: `false` when either string is not a plain path. -/
def pathStrWithin (base value : Str) : Bool :=
  match parsePath base, parsePath value with
  | some b, some v => within b v
  | _, _ => false

/-- The string a parsed path spells. Not a Rust function: the proof uses it to show that a
parsed path reads back as the string it came from. -/
def render (p : PathSegs) : Str :=
  (if p.absolute then ['/'] else [])
  ++ joinSlash p.segs
  ++ (if p.dir && !p.segs.isEmpty then ['/'] else [])

/-! ## Facts about paths -/

theorem within_refl (p : PathSegs) : within p p = true := by
  simp [within, List.isPrefixOf_iff_prefix]

theorem within_trans {a b c : PathSegs} (hab : within a b = true) (hbc : within b c = true) :
    within a c = true := by
  simp only [within, Bool.and_eq_true, beq_iff_eq, List.isPrefixOf_iff_prefix, Bool.or_eq_true,
    Bool.not_eq_true', decide_eq_true_eq] at hab hbc ⊢
  obtain ⟨⟨h1, h2⟩, h3⟩ := hab
  obtain ⟨⟨h4, h5⟩, h6⟩ := hbc
  have hl := h5.length_le
  have hl2 := h2.length_le
  refine ⟨⟨h1.trans h4, h2.trans h5⟩, ?_⟩
  rcases h3 with (h3 | h3) | h3 <;> rcases h6 with (h6 | h6) | h6
  all_goals first
    | exact Or.inl (Or.inl h3)
    | exact Or.inl (Or.inr h6)
    | (right; omega)
    | (simp_all)

theorem refused_of_double_slash (s : Str) (h : hasDoubleSlash s = true) : refused s = true := by
  simp [refused, h]

theorem not_double_slash_of_parse {s : Str} {p : PathSegs} (h : parsePath s = some p) :
    hasDoubleSlash s = false ∧ s ≠ [] := by
  have hr := (parsePath_eq h).1
  constructor
  · cases hd : hasDoubleSlash s
    · rfl
    · simp [refused_of_double_slash s hd] at hr
  · intro hs
    subst hs
    simp [refused] at hr

theorem joinSlash_segs (body : Str) :
    joinSlash (if body = [] then [] else splitSlash body) = body := by
  split
  · next h => simp [h, joinSlash]
  · exact joinSlash_splitSlash body

theorem segs_isEmpty (body : Str) :
    (if body = [] then ([] : List Str) else splitSlash body).isEmpty = body.isEmpty := by
  split
  · next h => simp_all
  · next h =>
    have hn := splitSlash_ne_nil body
    cases hs : splitSlash body with
    | nil => exact absurd hs hn
    | cons g gs =>
      cases body with
      | nil => exact absurd rfl h
      | cons => rfl

theorem getLast?_snoc_slash (u : Str) : (u ++ ['/']).getLast? = some '/' := by simp

theorem dropLast_snoc_slash (u : Str) : (u ++ ['/']).dropLast = u := by simp

/-- A parsed path renders as the string it was parsed from. -/
theorem render_parsePath {s : Str} {p : PathSegs} (h : parsePath s = some p) : render p = s := by
  obtain ⟨hd, hne⟩ := not_double_slash_of_parse h
  obtain ⟨-, rfl⟩ := parsePath_eq h
  simp only [render, segsOf, joinSlash_segs, segs_isEmpty]
  cases s with
  | nil => exact absurd rfl hne
  | cons c t =>
    by_cases hc : c = '/'
    · subst hc
      simp only [bodyOf, isAbsolute, endsWithSlash, List.head?_cons, decide_true, ite_true,
        List.tail_cons, stripLastSlash]
      by_cases ht : t.getLast? = some '/'
      · obtain ⟨u, rfl⟩ := List.getLast?_eq_some_iff.mp ht
        have hu : u ≠ [] := by
          rintro rfl
          simp [hasDoubleSlash] at hd
        have hl : ('/' :: (u ++ ['/'])).getLast? = some '/' := by
          rw [← List.cons_append]; exact getLast?_snoc_slash _
        rw [hl, getLast?_snoc_slash, dropLast_snoc_slash]
        simp [hu]
      · simp only [ht, ite_false]
        cases t with
        | nil => simp
        | cons x xs =>
          have hl : ('/' :: x :: xs).getLast? = (x :: xs).getLast? := by simp
          simp [hl, ht]
    · simp only [bodyOf, isAbsolute, endsWithSlash, List.head?_cons, Option.some.injEq, hc,
        decide_false, Bool.false_eq_true, ite_false, stripLastSlash]
      by_cases hs : (c :: t).getLast? = some '/'
      · obtain ⟨u, hu⟩ := List.getLast?_eq_some_iff.mp hs
        have hne' : u ≠ [] := by
          rintro rfl
          simp at hu
          exact hc hu.1
        rw [hu, getLast?_snoc_slash, dropLast_snoc_slash]
        simp [hne']
      · simp [hs]

/-- If `v` lies within `q`, the string `q` spells is a prefix of the string `v` spells. -/
theorem render_prefix_of_within {q v : PathSegs} (h : within q v = true) :
    render q <+: render v := by
  simp only [within, Bool.and_eq_true, beq_iff_eq, List.isPrefixOf_iff_prefix, Bool.or_eq_true,
    Bool.not_eq_true', decide_eq_true_eq] at h
  obtain ⟨⟨habs, hpre⟩, hdir⟩ := h
  obtain ⟨r, hr⟩ := hpre
  cases q with
  | mk qa qs qd =>
  cases v with
  | mk va vs vd =>
  simp only at habs hr hdir ⊢
  subst habs
  subst hr
  simp only [render]
  by_cases hr0 : r = []
  · subst hr0
    simp only [List.append_nil] at hdir ⊢
    cases qd
    · simp only [Bool.false_and, Bool.false_eq_true, ite_false, List.append_nil]
      exact List.prefix_append _ _
    · have : vd = true := by
        rcases hdir with (h | h) | h
        · simp at h
        · exact h
        · omega
      subst this
      exact List.prefix_refl _
  · by_cases hq0 : qs = []
    · subst hq0
      simp only [List.isEmpty_nil, Bool.not_true, Bool.and_false, Bool.false_eq_true, ite_false,
        joinSlash, List.append_nil, List.nil_append]
      exact ⟨joinSlash r ++ (if vd && !r.isEmpty then ['/'] else []), by simp [joinSlash]⟩
    · rw [joinSlash_append hq0 hr0]
      have key : ∀ (t : Str), t = [] ∨ t = ['/'] →
          (if qa = true then ['/'] else []) ++ joinSlash qs ++ t <+:
          (if qa = true then ['/'] else []) ++ (joinSlash qs ++ '/' :: joinSlash r) ++
            (if vd && !(qs ++ r).isEmpty then ['/'] else []) := by
        intro t ht
        rcases ht with rfl | rfl
        · exact ⟨'/' :: joinSlash r ++ (if vd && !(qs ++ r).isEmpty then ['/'] else []),
            by simp⟩
        · exact ⟨joinSlash r ++ (if vd && !(qs ++ r).isEmpty then ['/'] else []), by simp⟩
      apply key
      split
      · exact Or.inr rfl
      · exact Or.inl rfl

/-- Every string a `path_prefix` admits starts with the constraint's own path. This is the
fact behind Rust's `(PathPrefix(q), Prefix(p)) => q.starts_with(p)` case of `implies`. -/
theorem prefix_of_pathStrWithin {base value : Str} (h : pathStrWithin base value = true) :
    base <+: value := by
  unfold pathStrWithin at h
  split at h
  · next b v hb hv =>
    have := render_prefix_of_within h
    rwa [render_parsePath hb, render_parsePath hv] at this
  · simp at h

theorem pathStrWithin_trans {a b c : Str} (hab : pathStrWithin a b = true)
    (hbc : pathStrWithin b c = true) : pathStrWithin a c = true := by
  unfold pathStrWithin at *
  cases ha : parsePath a <;> cases hb : parsePath b <;> cases hc : parsePath c <;>
    simp_all
  exact within_trans hab hbc

theorem pathStrWithin_refl {a : Str} (h : (parsePath a).isSome) : pathStrWithin a a = true := by
  unfold pathStrWithin
  cases ha : parsePath a with
  | none => simp [ha] at h
  | some p => simp [within_refl]

end Attenuo
