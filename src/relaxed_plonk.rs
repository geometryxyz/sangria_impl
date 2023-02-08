use ark_ff::PrimeField;
use ark_std::marker::PhantomData;

/// A committed relaxed PLONK instance
pub struct RelaxedPLONKInstance<F: PrimeField> {
    _temp: PhantomData<F>,
}

/// A committed relaxed PLONK witness
pub struct RelaxedPLONKWitness<F: PrimeField> {
    _temp: PhantomData<F>,
}

/// A structure that hold the defining elements of a PLONK circuit
pub struct PLONKCircuit {}
