use crate::Config;

/// A trait for types that can be configured.
///
/// This trait defines a method `config` which returns a reference to a
/// `Config`.
pub trait Configurable {
    /// Returns a reference to the configuration of this type.
    ///
    /// # Examples
    ///
    /// ```
    /// let config = MyType::default().config();
    /// ```
    fn config(&self) -> &Config;
}
