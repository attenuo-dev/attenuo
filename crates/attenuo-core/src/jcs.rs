//! RFC 8785 JSON Canonicalization Scheme (JCS): one byte string per JSON value, for everything
//! that is hashed or signed.
//!
//! [`to_vec`] serializes any `Serialize` value straight to its canonical form:
//!
//! - no whitespace;
//! - object members sorted by their names compared as UTF-16 code units (RFC 8785 section
//!   3.2.3), whatever order the value holds them in, so `serde_json`'s `preserve_order`
//!   feature (switched on workspace-wide by a dependency) cannot change the bytes;
//! - strings escaped as section 3.2.2.2 says: `\"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`, other
//!   control characters as `\u00xx` (lowercase hex), everything else as UTF-8;
//! - numbers written as ECMAScript's `Number.prototype.toString` writes the IEEE 754 double
//!   (section 3.2.2.3): `1.0` is `1`, `1e30` is `1e+30`, `0.000001` stays `0.000001`.
//!
//! **Integers.** RFC 8785 models every number as a double. An integer whose magnitude is at
//! most 2^53 (I-JSON's exact range) has the same digits either way and is written as RFC 8785
//! writes it. A larger integer has no exact double; JCS would round it, which would give
//! different values the same bytes (and so the same digest). This module writes such an
//! integer with all of its digits instead. That is the only departure from RFC 8785, and it
//! only concerns values outside the RFC's (I-JSON's) domain.
//!
//! **Refused.** A non-finite float (JSON has no NaN or infinity), a map key that is not a
//! string (or an integer, written as its decimal string, as `serde_json` does), two members
//! with the same name, and `serde_json`'s raw (unparsed) values. A value decoded from JSON
//! never holds any of them.
//!
//! [`value_eq`] is the equality that goes with this encoding: two `serde_json::Value`s are
//! equal exactly when their canonical forms are, so `1` equals `1.0` and object member order
//! does not matter.

use std::cmp::Ordering;
use std::fmt;

use serde::ser::{self, Serialize};
use serde_json::Value;

/// Why a value has no canonical form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JcsError {
    /// NaN or an infinity.
    #[error("JSON has no NaN or infinite numbers")]
    NonFinite,
    /// Two members of one object have this name.
    #[error("duplicate object member `{0}`")]
    DuplicateKey(String),
    /// A map key that is neither a string nor an integer.
    #[error("object keys must be strings")]
    KeyNotString,
    /// Something JSON cannot hold, or that this module does not canonicalize (raw JSON, a
    /// 128-bit integer out of the 64-bit range).
    #[error("cannot canonicalize {0}")]
    Unsupported(String),
    /// An error raised by a `Serialize` implementation.
    #[error("{0}")]
    Custom(String),
}

impl ser::Error for JcsError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        JcsError::Custom(msg.to_string())
    }
}

/// The canonical (RFC 8785) encoding of `value`.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, JcsError> {
    let node = value.serialize(NodeSerializer)?;
    let mut out = Vec::with_capacity(128);
    write_node(&mut out, node)?;
    Ok(out)
}

/// [`to_vec`] as a `String` (the encoding is UTF-8).
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, JcsError> {
    let bytes = to_vec(value)?;
    // Built from `&str`s and ASCII only.
    Ok(String::from_utf8(bytes).expect("canonical JSON is UTF-8"))
}

/// Append the canonical encoding of the string `s` (with its quotes) to `out`.
pub fn write_str(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    let bytes = s.as_bytes();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: &[u8] = match b {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            0x08 => b"\\b",
            0x09 => b"\\t",
            0x0a => b"\\n",
            0x0c => b"\\f",
            0x0d => b"\\r",
            0x00..=0x1f => {
                out.extend_from_slice(&bytes[start..i]);
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX[usize::from(b >> 4)]);
                out.push(HEX[usize::from(b & 0xf)]);
                start = i + 1;
                continue;
            }
            _ => continue,
        };
        out.extend_from_slice(&bytes[start..i]);
        out.extend_from_slice(esc);
        start = i + 1;
    }
    out.extend_from_slice(&bytes[start..]);
    out.push(b'"');
}

/// The ECMAScript `Number.prototype.toString` form of a finite double (RFC 8785 section
/// 3.2.2.3). `None` for NaN and the infinities.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "lengths are at most 17 digits and the exponent is within +-324, so they fit i32; \
              each `as usize` follows a range check that makes it non-negative"
)]
pub fn format_f64(v: f64) -> Option<String> {
    if !v.is_finite() {
        return None;
    }
    if v == 0.0 {
        // Both zeros.
        return Some("0".to_string());
    }
    let mut out = String::new();
    if v < 0.0 {
        out.push('-');
    }
    // ECMAScript wants the fewest digits that read back as the same double and, among those,
    // the closest to its exact value, ties to even. Ryu computes exactly that digit string
    // (Rust's own `{}` rounds such ties up: 1424953923781206.25 would print as `...206.3`
    // where ECMAScript prints `...206.2`); only the layout below is ECMAScript's.
    let mut buf = ryu::Buffer::new();
    let printed = buf.format_finite(v.abs());
    let (mantissa, exp) = match printed.find(['e', 'E']) {
        Some(i) => (
            &printed[..i],
            printed[i + 1..].parse::<i32>().expect("ryu exponent"),
        ),
        None => (printed, 0),
    };
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let mut digits = format!("{int}{frac}");
    // ECMAScript's `n`: the value is 0.digits * 10^n.
    let mut n = int.len() as i32 + exp;
    let lead = digits.len() - digits.trim_start_matches('0').len();
    digits.drain(..lead);
    n -= lead as i32;
    digits.truncate(digits.trim_end_matches('0').len());
    let k = digits.len() as i32;
    if k <= n && n <= 21 {
        out.push_str(&digits);
        out.extend(std::iter::repeat_n('0', (n - k) as usize));
    } else if 0 < n && n <= 21 {
        out.push_str(&digits[..n as usize]);
        out.push('.');
        out.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', (-n) as usize));
        out.push_str(&digits);
    } else {
        out.push_str(&digits[..1]);
        if k > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if n - 1 < 0 { '-' } else { '+' });
        out.push_str(&(n - 1).abs().to_string());
    }
    Some(out)
}

/// Equality of two JSON values as their canonical forms compare: numbers by value (`1` equals
/// `1.0`), objects regardless of member order.
pub fn value_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => number_key(x) == number_key(y),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| value_eq(a, b))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| value_eq(v, w)))
        }
        _ => a == b,
    }
}

/// What a number is written as. A `serde_json::Number` always has one.
fn number_key(n: &serde_json::Number) -> String {
    if let Some(u) = n.as_u64() {
        u.to_string()
    } else if let Some(i) = n.as_i64() {
        i.to_string()
    } else {
        n.as_f64().and_then(format_f64).unwrap_or_default()
    }
}

/// Order two strings by their UTF-16 code units (RFC 8785 section 3.2.3).
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// A serialized value, before it is written out.
enum Node {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Str(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}

fn write_node(out: &mut Vec<u8>, node: Node) -> Result<(), JcsError> {
    match node {
        Node::Null => out.extend_from_slice(b"null"),
        Node::Bool(true) => out.extend_from_slice(b"true"),
        Node::Bool(false) => out.extend_from_slice(b"false"),
        Node::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Node::UInt(u) => out.extend_from_slice(u.to_string().as_bytes()),
        Node::Float(f) => {
            out.extend_from_slice(format_f64(f).ok_or(JcsError::NonFinite)?.as_bytes())
        }
        Node::Str(s) => write_str(out, &s),
        Node::Array(items) => {
            out.push(b'[');
            for (i, item) in items.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_node(out, item)?;
            }
            out.push(b']');
        }
        Node::Object(mut members) => {
            members.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
            if let Some(w) = members.windows(2).find(|w| w[0].0 == w[1].0) {
                return Err(JcsError::DuplicateKey(w[0].0.clone()));
            }
            out.push(b'{');
            for (i, (k, v)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_str(out, &k);
                out.push(b':');
                write_node(out, v)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// `serde_json`'s marker for an unparsed `RawValue`, which would otherwise look like a struct.
const RAW_VALUE_TOKEN: &str = "$serde_json::private::RawValue";

struct NodeSerializer;

impl ser::Serializer for NodeSerializer {
    type Ok = Node;
    type Error = JcsError;
    type SerializeSeq = SeqBuilder;
    type SerializeTuple = SeqBuilder;
    type SerializeTupleStruct = SeqBuilder;
    type SerializeTupleVariant = VariantBuilder<SeqBuilder>;
    type SerializeMap = MapBuilder;
    type SerializeStruct = MapBuilder;
    type SerializeStructVariant = VariantBuilder<MapBuilder>;

    fn serialize_bool(self, v: bool) -> Result<Node, JcsError> {
        Ok(Node::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<Node, JcsError> {
        Ok(Node::Int(v.into()))
    }
    fn serialize_i16(self, v: i16) -> Result<Node, JcsError> {
        Ok(Node::Int(v.into()))
    }
    fn serialize_i32(self, v: i32) -> Result<Node, JcsError> {
        Ok(Node::Int(v.into()))
    }
    fn serialize_i64(self, v: i64) -> Result<Node, JcsError> {
        Ok(Node::Int(v))
    }
    fn serialize_i128(self, v: i128) -> Result<Node, JcsError> {
        if let Ok(i) = i64::try_from(v) {
            Ok(Node::Int(i))
        } else if let Ok(u) = u64::try_from(v) {
            Ok(Node::UInt(u))
        } else {
            Err(JcsError::Unsupported(format!("the integer {v}")))
        }
    }
    fn serialize_u8(self, v: u8) -> Result<Node, JcsError> {
        Ok(Node::UInt(v.into()))
    }
    fn serialize_u16(self, v: u16) -> Result<Node, JcsError> {
        Ok(Node::UInt(v.into()))
    }
    fn serialize_u32(self, v: u32) -> Result<Node, JcsError> {
        Ok(Node::UInt(v.into()))
    }
    fn serialize_u64(self, v: u64) -> Result<Node, JcsError> {
        Ok(Node::UInt(v))
    }
    fn serialize_u128(self, v: u128) -> Result<Node, JcsError> {
        u64::try_from(v)
            .map(Node::UInt)
            .map_err(|_| JcsError::Unsupported(format!("the integer {v}")))
    }
    fn serialize_f32(self, v: f32) -> Result<Node, JcsError> {
        self.serialize_f64(v.into())
    }
    fn serialize_f64(self, v: f64) -> Result<Node, JcsError> {
        if v.is_finite() {
            Ok(Node::Float(v))
        } else {
            Err(JcsError::NonFinite)
        }
    }
    fn serialize_char(self, v: char) -> Result<Node, JcsError> {
        Ok(Node::Str(v.to_string()))
    }
    fn serialize_str(self, v: &str) -> Result<Node, JcsError> {
        Ok(Node::Str(v.to_string()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Node, JcsError> {
        // As `serde_json` writes bytes: an array of numbers.
        Ok(Node::Array(
            v.iter().map(|b| Node::UInt(u64::from(*b))).collect(),
        ))
    }
    fn serialize_none(self) -> Result<Node, JcsError> {
        Ok(Node::Null)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Node, JcsError> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Node, JcsError> {
        Ok(Node::Null)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<Node, JcsError> {
        Ok(Node::Null)
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<Node, JcsError> {
        Ok(Node::Str(variant.to_string()))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<Node, JcsError> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Node, JcsError> {
        Ok(Node::Object(vec![(
            variant.to_string(),
            value.serialize(NodeSerializer)?,
        )]))
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<SeqBuilder, JcsError> {
        Ok(SeqBuilder(Vec::with_capacity(len.unwrap_or(0))))
    }
    fn serialize_tuple(self, len: usize) -> Result<SeqBuilder, JcsError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(self, _: &'static str, len: usize) -> Result<SeqBuilder, JcsError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<VariantBuilder<SeqBuilder>, JcsError> {
        Ok(VariantBuilder {
            variant,
            inner: SeqBuilder(Vec::with_capacity(len)),
        })
    }
    fn serialize_map(self, len: Option<usize>) -> Result<MapBuilder, JcsError> {
        Ok(MapBuilder {
            members: Vec::with_capacity(len.unwrap_or(0)),
            key: None,
        })
    }
    fn serialize_struct(self, name: &'static str, len: usize) -> Result<MapBuilder, JcsError> {
        if name == RAW_VALUE_TOKEN {
            return Err(JcsError::Unsupported("raw JSON".into()));
        }
        self.serialize_map(Some(len))
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<VariantBuilder<MapBuilder>, JcsError> {
        Ok(VariantBuilder {
            variant,
            inner: MapBuilder {
                members: Vec::with_capacity(len),
                key: None,
            },
        })
    }
}

struct SeqBuilder(Vec<Node>);

impl SeqBuilder {
    fn push<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), JcsError> {
        self.0.push(value.serialize(NodeSerializer)?);
        Ok(())
    }
}

impl ser::SerializeSeq for SeqBuilder {
    type Ok = Node;
    type Error = JcsError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), JcsError> {
        self.push(value)
    }
    fn end(self) -> Result<Node, JcsError> {
        Ok(Node::Array(self.0))
    }
}

impl ser::SerializeTuple for SeqBuilder {
    type Ok = Node;
    type Error = JcsError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), JcsError> {
        self.push(value)
    }
    fn end(self) -> Result<Node, JcsError> {
        Ok(Node::Array(self.0))
    }
}

impl ser::SerializeTupleStruct for SeqBuilder {
    type Ok = Node;
    type Error = JcsError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), JcsError> {
        self.push(value)
    }
    fn end(self) -> Result<Node, JcsError> {
        Ok(Node::Array(self.0))
    }
}

struct MapBuilder {
    members: Vec<(String, Node)>,
    key: Option<String>,
}

impl ser::SerializeMap for MapBuilder {
    type Ok = Node;
    type Error = JcsError;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), JcsError> {
        self.key = Some(match key.serialize(NodeSerializer)? {
            Node::Str(s) => s,
            Node::Int(i) => i.to_string(),
            Node::UInt(u) => u.to_string(),
            _ => return Err(JcsError::KeyNotString),
        });
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), JcsError> {
        let key = self
            .key
            .take()
            .ok_or_else(|| JcsError::Custom("map value without a key".into()))?;
        self.members.push((key, value.serialize(NodeSerializer)?));
        Ok(())
    }
    fn end(self) -> Result<Node, JcsError> {
        Ok(Node::Object(self.members))
    }
}

impl ser::SerializeStruct for MapBuilder {
    type Ok = Node;
    type Error = JcsError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), JcsError> {
        self.members
            .push((key.to_string(), value.serialize(NodeSerializer)?));
        Ok(())
    }
    fn end(self) -> Result<Node, JcsError> {
        Ok(Node::Object(self.members))
    }
}

/// A tuple or struct variant: `{"Variant": [..]}` or `{"Variant": {..}}`, as `serde_json`
/// writes them.
struct VariantBuilder<B> {
    variant: &'static str,
    inner: B,
}

impl ser::SerializeTupleVariant for VariantBuilder<SeqBuilder> {
    type Ok = Node;
    type Error = JcsError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), JcsError> {
        self.inner.push(value)
    }
    fn end(self) -> Result<Node, JcsError> {
        Ok(Node::Object(vec![(
            self.variant.to_string(),
            Node::Array(self.inner.0),
        )]))
    }
}

impl ser::SerializeStructVariant for VariantBuilder<MapBuilder> {
    type Ok = Node;
    type Error = JcsError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), JcsError> {
        ser::SerializeStruct::serialize_field(&mut self.inner, key, value)
    }
    fn end(self) -> Result<Node, JcsError> {
        Ok(Node::Object(vec![(
            self.variant.to_string(),
            Node::Object(self.inner.members),
        )]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(text: &str) -> String {
        let v: Value = serde_json::from_str(text).unwrap();
        to_string(&v).unwrap()
    }

    // The known answers below are those of the RFC 8785 reference implementation
    // (https://github.com/cyberphone/json-canonicalization, Apache-2.0), whose `values` and
    // `weird` inputs are the examples of RFC 8785 sections 3.2.2 and 3.2.3.

    #[test]
    fn rfc8785_arrays() {
        assert_eq!(
            canon(r#"[56, {"d": true, "10": null, "1": [ ]}]"#),
            r#"[56,{"1":[],"10":null,"d":true}]"#
        );
    }

    #[test]
    fn rfc8785_french() {
        assert_eq!(
            canon(
                r#"{"peach": "This sorting order", "péché": "is wrong according to French",
                    "pêche": "but canonicalization MUST", "sin": "ignore locale"}"#
            ),
            r#"{"peach":"This sorting order","péché":"is wrong according to French","pêche":"but canonicalization MUST","sin":"ignore locale"}"#
        );
    }

    #[test]
    fn rfc8785_structures() {
        assert_eq!(
            canon(
                r#"{"1": {"f": {"f": "hi","F": 5} ,"\n": 56.0}, "10": { }, "": "empty",
                    "a": { }, "111": [ {"e": "yes","E": "no" } ], "A": { }}"#
            ),
            r#"{"":"empty","1":{"\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}"#
        );
    }

    #[test]
    fn rfc8785_unicode_is_not_normalized() {
        assert_eq!(
            canon(r#"{"Unnormalized Unicode":"A\u030a"}"#),
            "{\"Unnormalized Unicode\":\"A\u{030a}\"}"
        );
    }

    /// RFC 8785 section 3.2.2.
    #[test]
    fn rfc8785_values() {
        assert_eq!(
            canon(
                r#"{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
                    "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
                    "literals": [null, true, false]}"#
            ),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
        );
    }

    /// RFC 8785 section 3.2.3: sorting by UTF-16 code units, checked byte for byte against
    /// the reference implementation's `outhex/weird.txt`.
    #[test]
    fn rfc8785_weird_sorting() {
        let out = canon(
            r#"{"\u20ac": "Euro Sign", "\r": "Carriage Return", "\u000a": "Newline",
                "1": "One", "\u0080": "Control\u007f", "\ud83d\ude02": "Smiley",
                "\u00f6": "Latin Small Letter O With Diaeresis",
                "\ufb33": "Hebrew Letter Dalet With Dagesh", "</script>": "Browser Challenge"}"#,
        );
        let hex = "7b225c6e223a224e65776c696e65222c225c72223a2243617272696167652052\
                   657475726e222c2231223a224f6e65222c223c2f7363726970743e223a224272\
                   6f77736572204368616c6c656e6765222c22c280223a22436f6e74726f6c7f22\
                   2c22c3b6223a224c6174696e20536d616c6c204c6574746572204f2057697468\
                   20446961657265736973222c22e282ac223a224575726f205369676e222c22f0\
                   9f9882223a22536d696c6579222c22efacb3223a22486562726577204c657474\
                   65722044616c6574205769746820446167657368227d";
        assert_eq!(hex::encode(out.as_bytes()), hex);
    }

    /// RFC 8785 Appendix B: IEEE 754 doubles and their canonical form.
    #[test]
    fn rfc8785_appendix_b_numbers() {
        let cases: &[(u64, Option<&str>)] = &[
            (0x0000000000000000, Some("0")),
            (0x8000000000000000, Some("0")),
            (0x0000000000000001, Some("5e-324")),
            (0x8000000000000001, Some("-5e-324")),
            (0x7fefffffffffffff, Some("1.7976931348623157e+308")),
            (0xffefffffffffffff, Some("-1.7976931348623157e+308")),
            (0x4340000000000000, Some("9007199254740992")),
            (0xc340000000000000, Some("-9007199254740992")),
            (0x4430000000000000, Some("295147905179352830000")),
            (0x7fffffffffffffff, None),
            (0x7ff0000000000000, None),
            (0x44b52d02c7e14af5, Some("9.999999999999997e+22")),
            (0x44b52d02c7e14af6, Some("1e+23")),
            (0x44b52d02c7e14af7, Some("1.0000000000000001e+23")),
            (0x444b1ae4d6e2ef4e, Some("999999999999999700000")),
            (0x444b1ae4d6e2ef4f, Some("999999999999999900000")),
            (0x444b1ae4d6e2ef50, Some("1e+21")),
            (0x3eb0c6f7a0b5ed8c, Some("9.999999999999997e-7")),
            (0x3eb0c6f7a0b5ed8d, Some("0.000001")),
            (0x41b3de4355555553, Some("333333333.3333332")),
            (0x41b3de4355555554, Some("333333333.33333325")),
            (0x41b3de4355555555, Some("333333333.3333333")),
            (0x41b3de4355555556, Some("333333333.3333334")),
            (0x41b3de4355555557, Some("333333333.33333343")),
            (0xbecbf647612f3696, Some("-0.0000033333333333333333")),
            (0x43143ff3c1cb0959, Some("1424953923781206.2")),
        ];
        for &(bits, want) in cases {
            let v = f64::from_bits(bits);
            assert_eq!(format_f64(v).as_deref(), want, "{bits:016x}");
            match want {
                Some(w) => assert_eq!(to_string(&v).unwrap(), w),
                None => assert_eq!(to_string(&v), Err(JcsError::NonFinite)),
            }
        }
    }

    #[test]
    fn member_order_and_preserve_order_do_not_matter() {
        let a: Value = serde_json::from_str(r#"{"b":{"y":1,"x":2},"a":[{"d":0,"c":1}]}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":[{"c":1,"d":0}],"b":{"x":2,"y":1}}"#).unwrap();
        assert_eq!(to_vec(&a).unwrap(), to_vec(&b).unwrap());
        assert_eq!(
            to_string(&a).unwrap(),
            r#"{"a":[{"c":1,"d":0}],"b":{"x":2,"y":1}}"#
        );
        assert!(value_eq(&a, &b));
    }

    #[test]
    fn typed_values_match_their_json_value() {
        #[derive(serde::Serialize)]
        struct S {
            z: u8,
            a: Option<&'static str>,
            e: E,
            t: (i64, &'static str),
        }
        #[derive(serde::Serialize)]
        enum E {
            Tuple(u8, u8),
        }
        let s = S {
            z: 1,
            a: None,
            e: E::Tuple(1, 2),
            t: (-3, "x"),
        };
        assert_eq!(
            to_string(&s).unwrap(),
            r#"{"a":null,"e":{"Tuple":[1,2]},"t":[-3,"x"],"z":1}"#
        );
        assert_eq!(
            to_string(&s).unwrap(),
            to_string(&serde_json::to_value(&s).unwrap()).unwrap()
        );
    }

    #[test]
    fn integers_keep_every_digit() {
        assert_eq!(to_string(&u64::MAX).unwrap(), "18446744073709551615");
        assert_eq!(to_string(&i64::MIN).unwrap(), "-9223372036854775808");
        // Above 2^53 two integers would round to the same double; they stay distinct.
        assert_ne!(
            to_vec(&json!(9007199254740993u64)).unwrap(),
            to_vec(&json!(9007199254740992u64)).unwrap()
        );
        // Within 2^53, an integer and the equal double are the same number.
        assert_eq!(to_string(&json!(1.0)).unwrap(), "1");
        assert!(value_eq(&json!(1), &json!(1.0)));
        assert!(value_eq(&json!(-0.0), &json!(0)));
        assert!(!value_eq(&json!(1), &json!(1.5)));
        assert!(!value_eq(&json!("1"), &json!(1)));
    }

    #[test]
    fn refuses_what_json_cannot_hold() {
        assert_eq!(to_vec(&f64::NAN), Err(JcsError::NonFinite));
        assert_eq!(to_vec(&[f64::INFINITY]), Err(JcsError::NonFinite));
        let mut m = std::collections::BTreeMap::new();
        m.insert((1, 2), 3);
        assert_eq!(to_vec(&m), Err(JcsError::KeyNotString));
        #[derive(serde::Serialize)]
        struct Dup {
            a: u8,
            #[serde(rename = "a")]
            b: u8,
        }
        assert_eq!(
            to_vec(&Dup { a: 1, b: 2 }),
            Err(JcsError::DuplicateKey("a".into()))
        );
        // `serde_json`'s `RawValue` (unparsed JSON text) serializes as this marker struct.
        struct Raw;
        impl Serialize for Raw {
            fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use ser::SerializeStruct;
                let mut st = s.serialize_struct(RAW_VALUE_TOKEN, 1)?;
                st.serialize_field(RAW_VALUE_TOKEN, "{ }")?;
                st.end()
            }
        }
        assert!(matches!(to_vec(&Raw), Err(JcsError::Unsupported(_))));
    }

    #[test]
    fn control_characters_are_escaped_lowercase() {
        let s: String = (0u8..0x20).map(char::from).collect::<String>() + "\u{7f}\u{2028}/";
        let out = to_string(&s).unwrap();
        assert_eq!(
            out,
            "\"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\b\\t\\n\\u000b\\f\\r\
             \\u000e\\u000f\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\
             \\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f\u{7f}\u{2028}/\""
        );
        // Canonical output parses back to the same value.
        assert_eq!(serde_json::from_str::<String>(&out).unwrap(), s);
    }
}
