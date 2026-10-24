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
         session: SessionContext, args_contain_untrusted: Bool, untrusted_args: Set<String>, approval: ApprovalContext }}",
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
