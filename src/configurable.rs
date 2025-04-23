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
    /// ```rust, no_run
    /// # use openid::{Configurable, Config};
    /// # #[derive(Default)]
    /// # struct MyType;
    /// # impl Configurable for MyType { fn config(&self) -> &Config { todo!() }}
    /// let config = MyType::default().config();
    /// ```
    fn config(&self) -> &Config;
}
