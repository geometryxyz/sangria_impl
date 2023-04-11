//! Trait implementations for the Pasta curves.

use ark_pallas::Affine as PallasAffine;
use ark_pallas::Projective as PallasProjective;
use ark_pallas::{Fq, Fr};
use ark_vesta::Affine as VestaAffine;
use ark_vesta::Projective as VestaProjective;

// this is analogous to the ark_pallas::PallasParameters struct
/// A struct to hang the `CommitmentGroup` trait for Pallas on.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PallasGroup;

impl crate::pcs::CommitmentGroup for PallasGroup {
    type Fr = Fr;
    type G1Affine = PallasAffine;
    type G1Projective = PallasProjective;
    type Fq = Fq;
}

// this is analogous to the ark_pallas::VestaParameters struct
/// A struct to hang the `CommitmentGroup` trait for Vesta on.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VestaGroup;

impl crate::pcs::CommitmentGroup for VestaGroup {
    type Fr = Fq;
    type G1Affine = VestaAffine;
    type G1Projective = VestaProjective;
    type Fq = Fr;
}
