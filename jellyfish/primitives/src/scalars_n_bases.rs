//! A vector representation of bases and corresponding scalars
use crate::pcs::CommitmentGroup;
use ark_ec::msm::VariableBaseMSM;
use ark_ff::PrimeField;
use ark_std::Zero;
use hashbrown::HashMap;

/// The vector representation of bases and corresponding scalars.
#[derive(Debug)]
pub struct ScalarsAndBases<E: CommitmentGroup> {
    /// The scalars and bases collection
    pub base_scalar_map: HashMap<E::G1Affine, E::Fr>,
}

impl<E: CommitmentGroup> ScalarsAndBases<E> {
    /// Create an empty collection of scalars and bases.
    pub fn new() -> Self {
        Self {
            base_scalar_map: HashMap::new(),
        }
    }
    /// Insert a base point and the corresponding scalar.
    pub fn push(&mut self, scalar: E::Fr, base: E::G1Affine) {
        let entry_scalar = self.base_scalar_map.entry(base).or_insert_with(E::Fr::zero);
        *entry_scalar += scalar;
    }

    /// Add a list of scalars and bases into self, where each scalar is
    /// multiplied by a constant c.
    pub fn merge(&mut self, c: E::Fr, scalars_and_bases: &Self) {
        for (base, scalar) in &scalars_and_bases.base_scalar_map {
            self.push(c * scalar, *base);
        }
    }
    /// Compute the multi-scalar multiplication.
    pub fn multi_scalar_mul(&self) -> E::G1Projective {
        let mut bases = vec![];
        let mut scalars = vec![];
        for (base, scalar) in &self.base_scalar_map {
            bases.push(*base);
            scalars.push(scalar.into_repr());
        }
        VariableBaseMSM::multi_scalar_mul(&bases, &scalars)
    }
}
