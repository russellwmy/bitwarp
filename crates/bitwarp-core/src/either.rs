/// A type that can hold one of two possible values.
///
/// Used for type-level choices where a value can be either `L` or `R`.
#[derive(Debug)]
pub enum Either<L, R> {
    /// Left variant
    Left(L),
    /// Right variant
    Right(R),
}
