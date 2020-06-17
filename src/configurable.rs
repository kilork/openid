use crate::Config;

pub trait Configurable {
    fn config(&self) -> &Config;
}
