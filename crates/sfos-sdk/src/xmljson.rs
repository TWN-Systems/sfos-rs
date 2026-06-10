//! Generic XML → JSON conversion.
//!
//! Lets the SDK return *any* SFOS entity's data as structured JSON without a
//! hand-written typed struct — the basis for "pull everything, then report".
//! Elements become objects; repeated children become arrays; attributes are
//! prefixed `@`; mixed text is stored under `#text`.

use quick_xml::events::Event;
use quick_xml::Reader;

enum J {
    S(String),
    O(Vec<(String, J)>),
    A(Vec<J>),
}

struct Frame {
    name: String,
    children: Vec<(String, J)>,
    text: String,
}

/// Convert an XML document to a compact JSON string.
pub fn to_json(xml: &str) -> String {
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut stack: Vec<Frame> = vec![Frame { name: String::new(), children: Vec::new(), text: String::new() }];

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let mut f = Frame { name: name_of(e.name().as_ref()), children: Vec::new(), text: String::new() };
                push_attrs(&e, &mut f);
                stack.push(f);
            }
            Ok(Event::Empty(e)) => {
                let mut f = Frame { name: name_of(e.name().as_ref()), children: Vec::new(), text: String::new() };
                push_attrs(&e, &mut f);
                let name = f.name.clone();
                let node = frame_to_json(f);
                stack.last_mut().unwrap().children.push((name, node));
            }
            Ok(Event::Text(t)) => {
                if let Ok(txt) = t.unescape() {
                    let s = txt.trim();
                    if !s.is_empty() {
                        stack.last_mut().unwrap().text.push_str(s);
                    }
                }
            }
            Ok(Event::CData(t)) => {
                let s = String::from_utf8_lossy(t.as_ref()).into_owned();
                stack.last_mut().unwrap().text.push_str(s.trim());
            }
            Ok(Event::End(_)) if stack.len() > 1 => {
                let f = stack.pop().unwrap();
                let name = f.name.clone();
                let node = frame_to_json(f);
                stack.last_mut().unwrap().children.push((name, node));
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    let root = stack.pop().unwrap();
    let mut out = String::new();
    write_json(&frame_to_json(root), &mut out);
    out
}

fn push_attrs(e: &quick_xml::events::BytesStart, f: &mut Frame) {
    for a in e.attributes().flatten() {
        let k = format!("@{}", name_of(a.key.as_ref()));
        let v = a.unescape_value().map(|c| c.into_owned()).unwrap_or_default();
        f.children.push((k, J::S(v)));
    }
}

fn frame_to_json(f: Frame) -> J {
    if f.children.is_empty() {
        return J::S(f.text);
    }
    let mut order: Vec<String> = Vec::new();
    let mut groups: Vec<(String, Vec<J>)> = Vec::new();
    for (k, v) in f.children {
        if let Some(slot) = groups.iter_mut().find(|(name, _)| *name == k) {
            slot.1.push(v);
        } else {
            order.push(k.clone());
            groups.push((k, vec![v]));
        }
    }
    let _ = order;
    let mut obj: Vec<(String, J)> = Vec::new();
    for (k, mut vals) in groups {
        if vals.len() == 1 {
            obj.push((k, vals.pop().unwrap()));
        } else {
            obj.push((k, J::A(vals)));
        }
    }
    if !f.text.is_empty() {
        obj.push(("#text".to_string(), J::S(f.text)));
    }
    J::O(obj)
}

fn write_json(j: &J, out: &mut String) {
    match j {
        J::S(s) => {
            out.push('"');
            escape(s, out);
            out.push('"');
        }
        J::A(a) => {
            out.push('[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(v, out);
            }
            out.push(']');
        }
        J::O(o) => {
            out.push('{');
            for (i, (k, v)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                escape(k, out);
                out.push_str("\":");
                write_json(v, out);
            }
            out.push('}');
        }
    }
}

fn escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

fn name_of(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_children_become_array() {
        let json = to_json("<A><B>x</B><B>y</B></A>");
        assert_eq!(json, r#"{"A":{"B":["x","y"]}}"#);
    }

    #[test]
    fn attributes_and_mixed_text() {
        let json = to_json(r#"<C k="1">z</C>"#);
        assert_eq!(json, r##"{"C":{"@k":"1","#text":"z"}}"##);
    }

    #[test]
    fn nested_entity_response() {
        let json = to_json(r#"<Response><IPHost><Name>h</Name><IPAddress>10.0.0.1</IPAddress></IPHost></Response>"#);
        assert_eq!(json, r#"{"Response":{"IPHost":{"Name":"h","IPAddress":"10.0.0.1"}}}"#);
    }
}
