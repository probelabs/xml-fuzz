//! XML-aware mutation operators.
//!
//! Each operator targets a structural / encoding boundary where an XML parser
//! state machine transitions. Operators return a **new** `Vec<u8>` (never
//! mutate in place).

use rand::Rng;

const STRUCTURAL: &[u8] = b"<>/?=!\"'&;[]";

const INVALID_UTF8: &[&[u8]] = &[
    &[0xC0, 0xAF],
    &[0xC1, 0xBF],
    &[0xE0, 0x80, 0xAF],
    &[0xF0, 0x80, 0x80, 0x80],
    &[0xE0],
    &[0xF0, 0x80],
    &[0xFF],
    &[0xFE],
    &[0xED, 0xA0, 0x80],
];

pub type MutationFn = fn(&mut dyn rand::RngCore, &[u8]) -> Vec<u8>;

/// Registry of all XML-aware mutations.
pub const MUTATION_OPS: &[MutationFn] = &[
    truncate_after_open_angle,
    truncate_inside_tag_name,
    truncate_inside_attribute,
    truncate_inside_attr_value,
    truncate_after_doctype,
    truncate_inside_cdata,
    truncate_inside_comment,
    truncate_inside_pi,
    truncate_inside_entity_ref,
    inject_invalid_utf8,
    inject_overlong_utf8_in_text,
    byteflip_structural,
    unbalance_end_tag,
    swap_quote_style,
    inject_extra_root,
    inject_deep_open_tags,
    strip_random_closer,
    inject_nul_byte,
    corrupt_xmlns,
    duplicate_attribute,
    inject_entity_bomb_ref,
    truncate_xml_decl,
    mess_namespace_colon,
    inject_unclosed_cdata,
    split_tag_with_newline,
    inject_xinclude_element,
    flip_version_11,
    inject_bom_prefix,
];

/// Pick one operator at random.
pub fn apply_mutation(r: &mut impl Rng, data: &[u8]) -> Vec<u8> {
    if data.len() < 2 {
        return data.to_vec();
    }
    let op = MUTATION_OPS[r.gen_range(0..MUTATION_OPS.len())];
    op(&mut *r, data)
}

/// Apply `n` successive mutations.
pub fn apply_mutations(r: &mut impl Rng, data: &[u8], n: usize) -> Vec<u8> {
    let mut cur = data.to_vec();
    for _ in 0..n {
        cur = apply_mutation(r, &cur);
    }
    cur
}

fn find_bytes(data: &[u8], targets: &[u8]) -> Vec<usize> {
    data.iter()
        .enumerate()
        .filter_map(|(i, b)| targets.contains(b).then_some(i))
        .collect()
}

fn find_pattern(data: &[u8], pat: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if pat.is_empty() || data.len() < pat.len() {
        return out;
    }
    for i in 0..=data.len() - pat.len() {
        if &data[i..i + pat.len()] == pat {
            out.push(i);
        }
    }
    out
}

fn truncate_at(data: &[u8], idx: usize) -> Vec<u8> {
    data[..idx.min(data.len())].to_vec()
}

// --- truncations ---

pub fn truncate_after_open_angle(_r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let pos = find_bytes(data, b"<");
    if let Some(&i) = pos.last() {
        truncate_at(data, i + 1)
    } else {
        data.to_vec()
    }
}

pub fn truncate_inside_tag_name(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let opens = find_bytes(data, b"<");
    if opens.is_empty() {
        return data.to_vec();
    }
    let i = opens[r.gen_range(0..opens.len())];
    let end = (i + 1..data.len())
        .find(|&j| data[j] == b'>' || data[j] == b' ' || data[j] == b'/' || data[j] == b'\n')
        .unwrap_or(data.len());
    if end <= i + 1 {
        return data.to_vec();
    }
    let cut = r.gen_range(i + 1..end);
    truncate_at(data, cut)
}

pub fn truncate_inside_attribute(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let eqs = find_bytes(data, b"=");
    if eqs.is_empty() {
        return data.to_vec();
    }
    let i = eqs[r.gen_range(0..eqs.len())];
    truncate_at(data, i + 1)
}

pub fn truncate_inside_attr_value(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let quotes: Vec<usize> = data
        .iter()
        .enumerate()
        .filter_map(|(i, b)| (*b == b'"' || *b == b'\'').then_some(i))
        .collect();
    if quotes.len() < 2 {
        return data.to_vec();
    }
    let idx = r.gen_range(0..quotes.len() - 1);
    let a = quotes[idx];
    let b = quotes[idx + 1];
    if b <= a + 1 {
        return data.to_vec();
    }
    truncate_at(data, r.gen_range(a + 1..b))
}

pub fn truncate_after_doctype(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let hits = find_pattern(data, b"<!DOCTYPE");
    if hits.is_empty() {
        return truncate_after_open_angle(r, data);
    }
    let i = hits[r.gen_range(0..hits.len())];
    let cut = (i + 9).min(data.len());
    let extra = r.gen_range(0..12usize);
    truncate_at(data, (cut + extra).min(data.len()))
}

pub fn truncate_inside_cdata(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let hits = find_pattern(data, b"<![CDATA[");
    if hits.is_empty() {
        return data.to_vec();
    }
    let i = hits[r.gen_range(0..hits.len())] + 9;
    truncate_at(data, i.min(data.len()))
}

pub fn truncate_inside_comment(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let hits = find_pattern(data, b"<!--");
    if hits.is_empty() {
        return data.to_vec();
    }
    let i = hits[r.gen_range(0..hits.len())] + 4;
    truncate_at(data, i.min(data.len()))
}

pub fn truncate_inside_pi(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let hits = find_pattern(data, b"<?");
    if hits.is_empty() {
        return data.to_vec();
    }
    let i = hits[r.gen_range(0..hits.len())] + 2;
    truncate_at(data, (i + r.gen_range(0..8)).min(data.len()))
}

pub fn truncate_inside_entity_ref(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let amps = find_bytes(data, b"&");
    if amps.is_empty() {
        return data.to_vec();
    }
    let i = amps[r.gen_range(0..amps.len())];
    truncate_at(data, (i + 1 + r.gen_range(0..3)).min(data.len()))
}

pub fn truncate_xml_decl(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    if data.starts_with(b"<?xml") {
        let cut = r.gen_range(2..data.len().min(40).max(3));
        truncate_at(data, cut)
    } else {
        data.to_vec()
    }
}

// --- inject / corrupt ---

pub fn inject_invalid_utf8(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let seq = INVALID_UTF8[r.gen_range(0..INVALID_UTF8.len())];
    let mut out = data.to_vec();
    let pos = r.gen_range(0..=out.len());
    out.splice(pos..pos, seq.iter().copied());
    out
}

pub fn inject_overlong_utf8_in_text(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    // prefer after a '>'
    let gt = find_bytes(data, b">");
    let pos = if gt.is_empty() {
        r.gen_range(0..=data.len())
    } else {
        gt[r.gen_range(0..gt.len())] + 1
    };
    let mut out = data.to_vec();
    let p = pos.min(out.len());
    out.splice(p..p, [0xC0, 0xAF]);
    out
}

pub fn byteflip_structural(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let pos = find_bytes(data, STRUCTURAL);
    if pos.is_empty() {
        return data.to_vec();
    }
    let i = pos[r.gen_range(0..pos.len())];
    let mut out = data.to_vec();
    out[i] ^= 0x01;
    out
}

pub fn unbalance_end_tag(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let hits = find_pattern(data, b"</");
    if hits.is_empty() {
        let mut out = data.to_vec();
        out.extend_from_slice(b"</x>");
        return out;
    }
    let i = hits[r.gen_range(0..hits.len())];
    let mut out = data.to_vec();
    // rename end tag char
    if i + 2 < out.len() {
        out[i + 2] = b'Z';
    }
    out
}

pub fn swap_quote_style(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let quotes: Vec<usize> = out
        .iter()
        .enumerate()
        .filter_map(|(i, b)| (*b == b'"' || *b == b'\'').then_some(i))
        .collect();
    if quotes.is_empty() {
        return out;
    }
    let i = quotes[r.gen_range(0..quotes.len())];
    out[i] = if out[i] == b'"' { b'\'' } else { b'"' };
    out
}

pub fn inject_extra_root(_r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.extend_from_slice(b"<extra/>");
    out
}

pub fn inject_deep_open_tags(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let n = r.gen_range(20..80usize);
    let mut wrap = Vec::new();
    for _ in 0..n {
        wrap.extend_from_slice(b"<d>");
    }
    wrap.extend_from_slice(data);
    // leave unclosed
    wrap
}

pub fn strip_random_closer(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let hits = find_pattern(data, b"</");
    if hits.is_empty() {
        return data.to_vec();
    }
    let i = hits[r.gen_range(0..hits.len())];
    let end = (i..data.len())
        .find(|&j| data[j] == b'>')
        .map(|j| j + 1)
        .unwrap_or(data.len());
    let mut out = data[..i].to_vec();
    out.extend_from_slice(&data[end..]);
    out
}

pub fn inject_nul_byte(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let pos = r.gen_range(0..=out.len());
    out.insert(pos, 0);
    out
}

pub fn corrupt_xmlns(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let hits = find_pattern(data, b"xmlns");
    if hits.is_empty() {
        let mut out = data.to_vec();
        if let Some(i) = out.iter().position(|&b| b == b'>') {
            out.splice(i..i, b" xmlns:a=\"\"".iter().copied());
        }
        return out;
    }
    let i = hits[r.gen_range(0..hits.len())];
    let mut out = data.to_vec();
    if i + 5 < out.len() {
        out[i + 5] = b'X';
    }
    out
}

pub fn duplicate_attribute(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    // inject a="1" a="2" before first >
    if let Some(i) = data.iter().position(|&b| b == b'>') {
        let mut out = data[..i].to_vec();
        let frag = if r.gen_bool(0.5) {
            b" a=\"1\" a=\"2\""
        } else {
            b" x='y' x='z'"
        };
        out.extend_from_slice(frag);
        out.extend_from_slice(&data[i..]);
        out
    } else {
        data.to_vec()
    }
}

pub fn inject_entity_bomb_ref(_r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let mut out = b"<!DOCTYPE r [<!ENTITY a \"aaaa\"><!ENTITY b \"&a;&a;&a;&a;\">]>".to_vec();
    out.extend_from_slice(data);
    // try to insert &b; after first >
    if let Some(i) = out.iter().position(|&b| b == b'>') {
        out.splice(i + 1..i + 1, b"&b;".iter().copied());
    }
    out
}

pub fn inject_unclosed_cdata(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let pos = r.gen_range(0..=out.len());
    out.splice(pos..pos, b"<![CDATA[oops".iter().copied());
    out
}

pub fn mess_namespace_colon(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let colons = find_bytes(data, b":");
    if colons.is_empty() {
        let mut out = data.to_vec();
        if let Some(i) = out.iter().position(|&b| b == b'<') {
            if i + 1 < out.len() {
                out.insert(i + 1, b':');
            }
        }
        return out;
    }
    let i = colons[r.gen_range(0..colons.len())];
    let mut out = data.to_vec();
    out[i] = b'_';
    out
}

pub fn split_tag_with_newline(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let opens = find_bytes(data, b"<");
    if opens.is_empty() {
        return data.to_vec();
    }
    let i = opens[r.gen_range(0..opens.len())];
    let mut out = data.to_vec();
    if i + 1 <= out.len() {
        out.insert(i + 1, b'\n');
    }
    out
}

pub fn inject_xinclude_element(r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let frag = b"<xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" href=\"x.xml\"/>";
    let mut out = data.to_vec();
    let pos = if out.is_empty() {
        0
    } else {
        r.gen_range(0..=out.len())
    };
    out.splice(pos..pos, frag.iter().copied());
    out
}

pub fn flip_version_11(_r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    if let Some(i) = find_pattern(&out, b"version=\"1.0\"").into_iter().next() {
        out.splice(i..i + 13, b"version=\"1.1\"".iter().copied());
    } else if let Some(i) = find_pattern(&out, b"version='1.0'").into_iter().next() {
        out.splice(i..i + 13, b"version='1.1'".iter().copied());
    } else {
        let mut v = b"<?xml version=\"1.1\"?>".to_vec();
        v.extend_from_slice(&out);
        return v;
    }
    out
}

pub fn inject_bom_prefix(_r: &mut dyn rand::RngCore, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xEF, 0xBB, 0xBF];
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn mutation_changes_or_preserves() {
        let mut r = StdRng::seed_from_u64(7);
        let base = b"<?xml version=\"1.0\"?><a b=\"c\">x</a>";
        for _ in 0..30 {
            let m = apply_mutation(&mut r, base);
            assert!(!m.is_empty() || base.is_empty());
        }
    }

    #[test]
    fn truncate_after_angle_works() {
        let mut r = StdRng::seed_from_u64(1);
        let m = truncate_after_open_angle(&mut r, b"<root/>");
        assert!(m == b"<" || m.starts_with(b"<"));
    }
}
