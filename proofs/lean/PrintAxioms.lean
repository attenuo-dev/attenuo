/-
Prints the axioms each main theorem depends on. `scripts/check-lean.sh` runs this file and
fails if any axiom other than `propext`, `Quot.sound` and `Classical.choice` appears.
-/
import Attenuo

open Attenuo

#print axioms render_parsePath
#print axioms prefix_of_pathStrWithin
#print axioms pathStrWithin_trans
#print axioms Constraint.implies_sound
#print axioms Constraint.implies_refl
#print axioms Constraint.implies_trans
#print axioms patternCovers_sound
#print axioms patternCovers_refl
#print axioms patternCovers_trans
#print axioms Capability.coversCalls_sound
#print axioms Capability.covers_sound
#print axioms Capability.covers_refl
#print axioms Capability.covers_trans
#print axioms CapSet.covers_sound
#print axioms CapSet.covers_refl
#print axioms CapSet.covers_trans
#print axioms CapSet.attenuateWith_covered
#print axioms CapSet.attenuate_covered
#print axioms CapSet.attenuate_sound
#print axioms chain_permits_all
#print axioms chain_root_permits
#print axioms chainValid_extend
