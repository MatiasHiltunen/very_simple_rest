use vsr_core::error::{VsrError, VsrResult};

/// Case-insensitive HTTP fields with validated names, raw values and repeats.
/// Framework-specific header-map versions remain private to their adapters.
#[derive(Clone, Debug, Default)]
pub struct HeaderFields(::http::HeaderMap);

impl HeaderFields {
    /// Append a value without replacing earlier values for the same name.
    pub fn append(&mut self, name: &str, value: impl AsRef<[u8]>) -> VsrResult<()> {
        let name = ::http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| VsrError::Other("invalid HTTP header name".into()))?;
        let value = ::http::HeaderValue::from_bytes(value.as_ref())
            .map_err(|_| VsrError::Other("invalid HTTP header value".into()))?;
        self.0.append(name, value);
        Ok(())
    }

    /// First value for a name, without assuming text encoding.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.0.get(name).map(::http::HeaderValue::as_bytes)
    }

    /// All values for a name, preserving their relative order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> {
        self.0
            .get_all(name)
            .iter()
            .map(::http::HeaderValue::as_bytes)
    }

    /// Iterate normalized names and their values, including repeated fields.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.0
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeats_case_and_raw_values_survive() {
        let mut fields = HeaderFields::default();
        fields.append("Set-Cookie", "a=1").unwrap();
        fields.append("set-cookie", "b=2").unwrap();
        fields.append("x-opaque", [0x80]).unwrap();
        assert_eq!(
            fields.get_all("SET-cookie").collect::<Vec<_>>(),
            [b"a=1", b"b=2"]
        );
        assert_eq!(fields.get("X-Opaque"), Some(&[0x80][..]));
        assert!(fields.append("invalid name", "value").is_err());
        assert!(
            fields
                .append("x-header", "value\r\ninjected: true")
                .is_err()
        );
    }
}
