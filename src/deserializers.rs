use de::Visitor;
use serde::de;
use serde::Deserializer;

pub fn bool_from_str_or_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(BoolOrStringVisitor)
}

struct BoolOrStringVisitor;

impl<'de> Visitor<'de> for BoolOrStringVisitor {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a boolean or string of \"true\", \"false\".")
    }

    fn visit_bool<E>(self, value: bool) -> Result<bool, E>
    where
        E: de::Error,
    {
        Ok(value)
    }

    fn visit_str<E>(self, value: &str) -> Result<bool, E>
    where
        E: de::Error,
    {
        match value {
            "true" => Ok(true),
            "false" => Ok(false),
            _s => Err(E::custom(format!("Unknown string value: {}", _s))),
        }
    }
}
