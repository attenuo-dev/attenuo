// Suite policy for `github`. Frozen before the test split was written: its SHA-256 is in
// ../cases/test/POLICY_HASHES.json and run.py refuses test numbers if it changes.
// Suite-level policy (G0), the demo's policy extended: issue metadata is readable in any of
// alice's repositories, file contents only in public ones, and writes go only to public
// repositories. delete_repo has no permit at all.
@id("github_issue_reads")
permit(principal, action in [Action::"github/list_issues", Action::"github/get_issue"], resource)
when { context.input has repo && context.input.repo like "alice/*" };

@id("github_read_public_files_only")
permit(principal, action == Action::"github/read_file", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };

@id("github_write_public_repos_only")
permit(principal, action in
  [Action::"github/create_issue", Action::"github/add_issue_comment",
   Action::"github/create_pull_request"], resource)
when { context.input has repo && context.input.repo like "alice/public-*" };
