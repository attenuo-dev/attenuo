/-
Concrete cases from the Rust unit tests and doc comments, evaluated in the model by the
kernel (`decide`). They check that the model's definitions give the answers the Rust code
gives on these inputs; they prove nothing about other inputs.
-/
import Attenuo.Chain

namespace Attenuo.Examples

open Constraint

/-- `path_prefix` examples from the `ArgConstraint::PathPrefix` doc comment. -/
example : pathStrWithin "/workspace".toList "/workspace".toList = true := by decide
example : pathStrWithin "/workspace".toList "/workspace/a/b.txt".toList = true := by decide
example : pathStrWithin "/workspace".toList "/workspace-secrets/x".toList = false := by decide
example : pathStrWithin "/workspace".toList "/workspace/../etc/passwd".toList = false := by
  decide
example : pathStrWithin "/workspace/".toList "/workspace/".toList = true := by decide
example : pathStrWithin "/workspace/".toList "/workspace/a".toList = true := by decide
example : pathStrWithin "/workspace/".toList "/workspace".toList = false := by decide
example : pathStrWithin "/workspace".toList "workspace/a".toList = false := by decide
example : pathStrWithin "/workspace".toList "/workspace/%2e%2e/x".toList = false := by decide
example : pathStrWithin "/workspace".toList "/workspace//x".toList = false := by decide

/-- `pattern_covers` cases from the Rust test `exact_and_glob_patterns`. -/
example : patternCovers "*".toList "github".toList = true := by decide
example : patternCovers "git*".toList "github".toList = true := by decide
example : patternCovers "git*".toList "gith*".toList = true := by decide
example : patternCovers "gith*".toList "git*".toList = false := by decide
example : patternCovers "github".toList "*".toList = false := by decide
example : patternCovers "github".toList "git*".toList = false := by decide
example : patternCovers "github".toList "github".toList = true := by decide
example : patternCovers "github".toList "gitlab".toList = false := by decide

/-- `implies` cases from the Rust test `constraint_implication`, on the toy values. -/
abbrev C := Constraint ToyValue
def eqApi : C := .equals (.str "acme/api".toList)
def oneApiWeb : C := .oneOf [.str "acme/api".toList, .str "acme/web".toList]
def preAcme : C := .strPrefix "acme/".toList

example : eqApi.implies eqApi = true := by decide
example : eqApi.implies oneApiWeb = true := by decide
example : eqApi.implies preAcme = true := by decide
example : oneApiWeb.implies eqApi = false := by decide
example : oneApiWeb.implies preAcme = true := by decide
example : preAcme.implies eqApi = false := by decide
example : preAcme.implies oneApiWeb = false := by decide
example : (Constraint.strPrefix "acme/a".toList : C).implies preAcme = true := by decide
example : preAcme.implies (.strPrefix "acme/a".toList) = false := by decide
example : (Constraint.oneOf [] : C).implies eqApi = true := by decide
example : (Constraint.oneOf [] : C).sat (.str "acme/api".toList) = false := by decide

/-- Ranges and path prefixes against each other. -/
example : (Constraint.range (some 0) (some 10) : C).implies (.range (some 0) (some 2000)) = true := by decide
example : (Constraint.range (some 0) (some 2001) : C).implies (.range (some 0) (some 2000)) = false := by
  decide
example : (Constraint.range (some 5) (some 5) : C).implies (.equals (.int 5)) = true := by decide
example : (Constraint.equals (.int 7) : C).implies (.range none (some 10)) = true := by decide
example : (Constraint.pathPrefix "/workspace/a".toList : C).implies (.pathPrefix "/workspace".toList) = true :=
  by decide
example : (Constraint.pathPrefix "/workspace".toList : C).implies (.strPrefix "/work".toList) = true := by
  decide
example : (Constraint.strPrefix "/workspace/".toList : C).implies (.pathPrefix "/workspace".toList) = false :=
  by decide

end Attenuo.Examples
