//! Cedar schema: a fixed entity model plus a generated action model.
//!
//! The final schema the engine validates against is the concatenation of
//!
//! 1. the *base* schema ([`DEFAULT_SCHEMA`], or whatever was passed to
//!    `PolicyEngineBuilder::with_schema_str`), which declares the entity types; and
//! 2. a generated fragment with the common context types, the `UserAttributes` record, the
//!    generic `invoke` action and one action per catalog entry, `Action::"<server>/<tool>"`
//!    (one per distinct tool name, `Action::"<tool>"`, under `[policy] legacy_bare_actions`).
//!
//! Cedar requires every action a policy names to be declared, and it treats record types as
//! closed, so neither tool names nor argument names can be left open-ended in the schema.
//! Generating them from the catalog keeps validation honest without asking policy authors to
//! maintain a schema by hand.

use std::collections::BTreeMap;

use crate::catalog::{ArgType, ToolCatalog};

/// Name of the generic action every tool action is a member of. Policies that should apply to
/// every tool can be written as `action in Action::"invoke"` (or simply `action`).
pub const GENERIC_ACTION: &str = "invoke";

/// The default base schema: entity types only. Actions and context types are generated.
///
/// Entity model:
///
/// - `User` is the originating user. Attributes mirror `OriginatingUser`.
/// - `Agent` is a hop in the delegation chain. `principal` is always an `Agent`. An agent is
///   `in` the originating `User` and `in` every agent earlier in the chain, so both
///   `principal in User::"alice"` and `principal in Agent::"planner"` work.
/// - `Server` is a logical tool server (an MCP server, for instance).
/// - `Tool` is one tool on one server, with id `"<server>/<tool>"`, `in` its `Server`.
pub const DEFAULT_SCHEMA: &str = r#"// attenuo default Cedar schema (entity types).
// Actions, context types and UserAttributes are generated from the tool catalog.

entity User {
    subject: String,
    issuer: String,
    authenticated_at_unix: Long,
    attributes: UserAttributes,
};

entity Agent in [User, Agent] {
    id: String,
    chain_depth: Long,
};

entity Server {
    name: String,
};

entity Tool in [Server] {
    server: String,
    name: String,
    readonly: Bool,
    sensitive: Bool,
    destructive: Bool,
};
"#;

/// Entity types a base schema must declare, without a namespace.
pub const REQUIRED_ENTITY_TYPES: [&str; 4] = ["User", "Agent", "Server", "Tool"];

/// Policies that type-check without errors or warnings only when a schema declares what the
/// engine relies on: the entity types of [`DEFAULT_SCHEMA`] with each of their attributes
/// (required, of the same type), `Agent in [User, Agent]` and `Tool in [Server]`. They are
/// validated, never loaded.
const REQUIRED_SHAPE_PROBES: &str = r#"
@id("User, Agent, Server and Tool attributes")
permit(principal, action in Action::"invoke", resource) when {
  principal.id like "*" && principal.chain_depth > 0 &&
  resource.server like "*" && resource.name like "*" &&
  resource.readonly && resource.sensitive && resource.destructive &&
  User::"u".subject like "*" && User::"u".issuer like "*" &&
  User::"u".authenticated_at_unix > 0 &&
  User::"u".attributes == context.originating_user.attributes
};
@id("Agent in User")
permit(principal in User::"u", action in Action::"invoke", resource);
@id("Agent in Agent")
permit(principal in Agent::"a", action in Action::"invoke", resource);
@id("Tool in Server")
permit(principal, action in Action::"invoke", resource in Server::"s");
"#;

/// The required entity types a base schema's text does not declare (`entity A, B ...`), found
/// with a small tokenizer that skips `//` comments. Run before parsing, because the generated
/// fragment names `Agent` and `Tool`, so a base without them fails to parse with a less
/// helpful "failed to resolve types".
pub(crate) fn missing_entity_types(base: &str) -> Vec<&'static str> {
    let mut tokens: Vec<String> = Vec::new();
    for line in base.lines() {
        let code = line.split("//").next().unwrap_or("");
        let mut ident = String::new();
        for c in code.chars() {
            if c.is_alphanumeric() || c == '_' {
                ident.push(c);
                continue;
            }
            if !ident.is_empty() {
                tokens.push(std::mem::take(&mut ident));
            }
            if !c.is_whitespace() {
                tokens.push(c.to_string());
            }
        }
        if !ident.is_empty() {
            tokens.push(ident);
        }
    }
    let mut declared = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] == "entity" {
            i += 1;
            while i < tokens.len() {
                declared.push(tokens[i].clone());
                if tokens.get(i + 1).map(String::as_str) == Some(",") {
                    i += 2;
                } else {
                    break;
                }
            }
        }
        i += 1;
    }
    REQUIRED_ENTITY_TYPES
        .iter()
        .copied()
        .filter(|t| !declared.iter().any(|d| d == t))
        .collect()
}

/// Check that a complete schema (a custom base plus the generated fragment) still declares
/// what the engine builds requests from. `Err` lists what is missing.
pub(crate) fn check_required_shape(schema: &cedar_policy::Schema) -> Result<(), String> {
    let declared: Vec<String> = schema.entity_types().map(|t| t.to_string()).collect();
    let missing: Vec<&str> = REQUIRED_ENTITY_TYPES
        .iter()
        .copied()
        .filter(|t| !declared.iter().any(|d| d == t))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "it does not declare the entity type(s) {}",
            missing.join(", ")
        ));
    }
    let probes: cedar_policy::PolicySet = REQUIRED_SHAPE_PROBES
        .parse()
        .map_err(|e| format!("internal: probe policies: {e}"))?;
    let probes = crate::apply_id_annotations(&probes).map_err(|e| e.to_string())?;
    let result = cedar_policy::Validator::new(schema.clone())
        .validate(&probes, cedar_policy::ValidationMode::Strict);
    let mut problems: Vec<String> = result
        .validation_errors()
        .map(|e| format!("[{}] {e}", e.policy_id()))
        .chain(
            result
                .validation_warnings()
                .map(|w| format!("[{}] {w}", w.policy_id())),
        )
        .collect();
    problems.dedup();
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "it does not declare the entities attenuo builds requests from as the default \
             schema does (each attribute required and of the same type, `Agent in [User, Agent]`, \
             `Tool in [Server]`): {}",
            problems.join("; ")
        ))
    }
}

/// Attributes of the originating user that the default schema declares, so the starter
/// policies validate out of the box. All optional; override or extend them with
/// `PolicyEngineBuilder::with_user_attr`.
pub fn default_user_attrs() -> BTreeMap<String, ArgType> {
    BTreeMap::from([
        ("mfa".to_string(), ArgType::Bool),
        ("roles".to_string(), ArgType::Set(Box::new(ArgType::String))),
        ("tenant".to_string(), ArgType::String),
        ("email".to_string(), ArgType::String),
    ])
}

/// Quote a name for use as a Cedar schema attribute or action name.
fn quote(name: &str) -> String {
    let mut s = String::with_capacity(name.len() + 2);
    s.push('"');
    for c in name.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

fn record(attrs: &BTreeMap<String, ArgType>) -> String {
    let mut s = String::from("{");
    for (i, (name, ty)) in attrs.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push(' ');
        s.push_str(&quote(name));
        s.push_str("?: ");
        s.push_str(&ty.cedar());
    }
    if !attrs.is_empty() {
        s.push(' ');
    }
    s.push('}');
    s
}

fn context_type(inputs: &BTreeMap<String, ArgType>) -> String {
    format!(
        "{{ input: {}, originating_user: UserContext, chain: ChainContext, session_id?: String, now_unix: Long, \
         session: SessionContext, args_contain_untrusted: Bool, untrusted_args: Set<String>, approval: ApprovalContext, \
         budget: BudgetContext, usage: UsageContext }}",
        record(inputs)
    )
}

/// The Cedar action id of a call: `"<server>/<tool>"`, or the bare `"<tool>"` in legacy mode.
///
/// Server names never contain `/` ([`attenuo_core::names`]), so the id splits back into one
/// `(server, tool)` pair at its first `/`, and a permit for `github`'s `read_file` cannot
/// match `evil/read_file` (SR-13).
pub fn action_id(server: &str, tool: &str, legacy_bare_actions: bool) -> String {
    if legacy_bare_actions {
        tool.to_string()
    } else {
        format!("{server}/{tool}")
    }
}

/// Build the complete schema text from a base schema, the catalog and the user attributes.
/// With `legacy_bare_actions`, actions are declared per tool name (the form before SR-13).
pub fn generate(
    base: &str,
    catalog: &ToolCatalog,
    user_attrs: &BTreeMap<String, ArgType>,
    legacy_bare_actions: bool,
) -> String {
    let mut s = String::from(base);
    s.push_str("\n// ---- generated by attenuo-policy from the tool catalog ----\n");
    s.push_str(&format!("type UserAttributes = {};\n", record(user_attrs)));
    s.push_str(
        "type UserContext = { subject: String, issuer: String, authenticated_at_unix: Long, attributes: UserAttributes };\n",
    );
    s.push_str(
        "type ChainContext = { depth: Long, agents: Set<String>, root_agent: String, leases: Set<String> };\n",
    );
    // Output labelling (ADR-0009). Always present in the context, so policies need no `has`.
    s.push_str("type SessionContext = { tainted: Bool, tainted_by: Set<String> };\n");
    s.push_str("type ApprovalContext = { present: Bool, by: String };\n");
    // Run limits (ADR-0010). Always present too.
    s.push_str(
        "type BudgetContext = { limited: Bool, calls_remaining: Long, amount_remaining: Long, destination_new: Bool };\n",
    );
    // Run usage (run-limits design section 3.5). Always present.
    s.push_str("type UsageContext = { calls: Long, amount: Long, destination_seen: Bool };\n");
    let actions = catalog.actions(legacy_bare_actions);
    let mut all_inputs: BTreeMap<String, ArgType> = BTreeMap::new();
    for inputs in actions.values() {
        for (name, ty) in inputs {
            all_inputs.entry(name.clone()).or_insert_with(|| ty.clone());
        }
    }
    s.push_str(&format!(
        "action {} appliesTo {{ principal: Agent, resource: Tool, context: {} }};\n",
        quote(GENERIC_ACTION),
        context_type(&all_inputs)
    ));
    for (action, inputs) in &actions {
        if action == GENERIC_ACTION {
            continue;
        }
        s.push_str(&format!(
            "action {} in {} appliesTo {{ principal: Agent, resource: Tool, context: {} }};\n",
            quote(action),
            quote(GENERIC_ACTION),
            context_type(inputs)
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::ToolAttrs;

    fn build_with_base(base: &str, policies: &str) -> Result<crate::PolicyEngine, String> {
        crate::PolicyEngineBuilder::new()
            .with_catalog(ToolCatalog::new().with("github", "read_file", ToolAttrs::new()))
            .with_schema_str(base)
            .with_policies_str(policies)
            .build()
            .map_err(|e| e.to_string())
    }

    #[test]
    fn a_custom_base_that_extends_the_default_is_accepted() {
        let base = DEFAULT_SCHEMA.replace(
            "    destructive: Bool,\n",
            "    destructive: Bool,\n    owner?: String,\n",
        ) + "\nentity Team;\n";
        assert!(base.contains("owner?: String"));
        let engine = build_with_base(
            &base,
            r#"@id("own") permit(principal, action, resource) when { resource has owner && resource.owner == "alice" };"#,
        )
        .unwrap();
        assert!(engine.schema_text().contains("entity Team;"));
        // The same policy does not validate against the default base.
        let err = build_with_base(
            DEFAULT_SCHEMA,
            r#"permit(principal, action, resource) when { resource.owner == "alice" };"#,
        );
        assert!(err.is_err());
        // The default base passes the shape check itself.
        let default = cedar_policy::Schema::from_cedarschema_str(&generate(
            DEFAULT_SCHEMA,
            &ToolCatalog::new(),
            &default_user_attrs(),
            false,
        ))
        .unwrap()
        .0;
        check_required_shape(&default).unwrap();
    }

    #[test]
    fn a_custom_base_missing_what_the_engine_needs_is_refused() {
        let refused = |base: String, want: &str| {
            let err = build_with_base(&base, "").unwrap_err();
            assert!(
                err.starts_with("schema error: custom base schema: "),
                "{err}"
            );
            assert!(err.contains(want), "want {want:?} in {err}");
        };
        // A missing entity type.
        let no_tool = DEFAULT_SCHEMA
            .split("entity Tool")
            .next()
            .unwrap()
            .replace("Tool in [Server]", "")
            .to_string();
        refused(no_tool, "does not declare the entity type(s) Tool");
        // An attribute made optional, or retyped.
        refused(
            DEFAULT_SCHEMA.replace("readonly: Bool", "readonly?: Bool"),
            "readonly",
        );
        refused(DEFAULT_SCHEMA.replace("id: String", "id: Long"), "Agent");
        // The hierarchy: an agent must be `in` its user.
        refused(
            DEFAULT_SCHEMA.replace("entity Agent in [User, Agent]", "entity Agent in [Agent]"),
            "Agent in User",
        );
        // Actions are generated; declaring one collides.
        refused(format!("{DEFAULT_SCHEMA}\naction \"invoke\";\n"), "invoke");
        // A base that does not parse at all.
        refused("entity User {".to_string(), "custom base schema");
    }

    #[test]
    fn quotes_and_escapes_names() {
        assert_eq!(quote("plain"), "\"plain\"");
        assert_eq!(quote("we\"ird\\"), "\"we\\\"ird\\\\\"");
    }

    #[test]
    fn generated_schema_parses() {
        let catalog = ToolCatalog::new()
            .with(
                "github",
                "create_issue",
                ToolAttrs::new().with_input("repo", ArgType::String),
            )
            .with("fs", "read-file", ToolAttrs::new().readonly(true))
            .with("x", "invoke", ToolAttrs::new());
        let text = generate(DEFAULT_SCHEMA, &catalog, &default_user_attrs(), false);
        let (_, warnings) =
            cedar_policy::Schema::from_cedarschema_str(&text).expect("schema parses");
        assert_eq!(warnings.count(), 0);
        assert!(text.contains("action \"github/create_issue\" in \"invoke\""));
        assert!(text.contains("action \"fs/read-file\" in \"invoke\""));
        assert!(text.contains("action \"x/invoke\" in \"invoke\""));
        assert!(!text.contains("action \"create_issue\""));
        // Output labelling attributes are declared for every action.
        for attr in [
            "destructive: Bool",
            "session: SessionContext",
            "args_contain_untrusted: Bool",
            "untrusted_args: Set<String>",
            "approval: ApprovalContext",
            "type SessionContext = { tainted: Bool, tainted_by: Set<String> }",
            "type ApprovalContext = { present: Bool, by: String }",
            "budget: BudgetContext",
            "type BudgetContext = { limited: Bool, calls_remaining: Long, amount_remaining: Long, destination_new: Bool }",
            "usage: UsageContext",
            "type UsageContext = { calls: Long, amount: Long, destination_seen: Bool }",
        ] {
            assert!(text.contains(attr), "{attr}");
        }
        assert_eq!(text.matches("action \"invoke\"").count(), 1);

        let legacy = generate(DEFAULT_SCHEMA, &catalog, &default_user_attrs(), true);
        let _ = cedar_policy::Schema::from_cedarschema_str(&legacy).expect("legacy schema parses");
        assert!(legacy.contains("action \"create_issue\" in \"invoke\""));
        assert!(legacy.contains("action \"read-file\" in \"invoke\""));
        // a tool literally named `invoke` collapses into the generic action
        assert_eq!(legacy.matches("action \"invoke\"").count(), 1);
    }
}
