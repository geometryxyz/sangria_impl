use ark_ff::{Field, PrimeField};
use ark_sponge::Absorb;
use std::ops::{Add, Mul};

use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::{folding_scheme::FoldingCommitmentConfig, SangriaError};

type ColumnVector<F> = Vec<F>;
type Permutation<F> = Vec<F>;

/// A constant variable for the q_L selector's index
pub const LEFT_SELECTOR_INDEX: usize = 0;

/// A constant variable for the q_R selector's index
pub const RIGHT_SELECTOR_INDEX: usize = 1;

/// A constant variable for the q_O selector's index
pub const OUTPUT_SELECTOR_INDEX: usize = 2;

/// A constant variable for the q_M selector's index
pub const MULTIPLICATION_SELECTOR_INDEX: usize = 3;

/// A constant variable for the q_C selector's index
pub const CONSTANT_SELECTOR_INDEX: usize = 4;

/// A committed relaxed PLONK instance
pub struct RelaxedPLONKInstance<F: PrimeField, Comm: FoldingCommitmentConfig<F>> {
    plonk_instance: PLONKInstance<F>,
    scaling_factor: F,
    slack_commitment: <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::Commitment,
    witness_commitments:
        Vec<<Comm::CommitmentWitness as HomomorphicCommitmentScheme<F>>::Commitment>,
}

impl<F: PrimeField, Comm: FoldingCommitmentConfig<F>> RelaxedPLONKInstance<F, Comm> {
    /// Returns the i-th column of the PLONK instance or an error if index is out of bounds.
    pub fn instance_column(&self, column_index: usize) -> Result<ColumnVector<F>, SangriaError> {
        self.plonk_instance.column(column_index)
    }

    /// Returns the i-th row of the PLONK instance or an error if index is out of bounds.
    pub fn instance_row(&self, row_index: usize) -> Result<Vec<F>, SangriaError> {
        self.plonk_instance.row(row_index)
    }

    /// Returns the scaling factor of the relaxed PLONK instance.
    pub fn scaling_factor(&self) -> F {
        self.scaling_factor
    }

    /// Returns the commitment to the slack vector.
    pub fn slack_commitment(
        &self,
    ) -> <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::Commitment {
        self.slack_commitment
    }

    /// Returns all the witness commitments.
    pub fn witness_commitments(
        &self,
    ) -> Vec<<Comm::CommitmentWitness as HomomorphicCommitmentScheme<F>>::Commitment> {
        self.witness_commitments.clone()
    }

    /// Returns a commitment to the i-th row of the witness or an error if index is out of bounds.
    pub fn single_witness_commitment(
        &self,
        column_index: usize,
    ) -> Result<<Comm::CommitmentWitness as HomomorphicCommitmentScheme<F>>::Commitment, SangriaError>
    {
        if column_index > self.witness_commitments.len() {
            return Err(SangriaError::IndexOutOfBounds);
        }

        Ok(self.witness_commitments[column_index])
    }
}

impl<F, Comm> Absorb for RelaxedPLONKInstance<F, Comm>
where
    F: PrimeField,
    Comm: FoldingCommitmentConfig<F>,
{
    fn to_sponge_bytes(&self, _dest: &mut Vec<u8>) {
        todo!()
    }

    fn to_sponge_field_elements<SpongeF: PrimeField>(&self, _dest: &mut Vec<SpongeF>) {
        todo!()
    }
}

impl<F, Comm> Add<&Self> for RelaxedPLONKInstance<F, Comm>
where
    F: PrimeField,
    Comm: FoldingCommitmentConfig<F>,
{
    type Output = Self;

    fn add(self, _rhs: &Self) -> Self::Output {
        todo!()
    }
}

impl<F, Comm> Mul<F> for RelaxedPLONKInstance<F, Comm>
where
    F: PrimeField,
    Comm: FoldingCommitmentConfig<F>,
{
    type Output = Self;

    fn mul(self, _rhs: F) -> Self::Output {
        todo!()
    }
}

impl<F, Comm> Clone for RelaxedPLONKInstance<F, Comm>
where
    F: PrimeField,
    Comm: FoldingCommitmentConfig<F>,
{
    fn clone(&self) -> Self {
        todo!()
    }
}

/// A committed relaxed PLONK witness.
pub struct RelaxedPLONKWitness<F: PrimeField> {
    plonk_witness: PLONKWitness<F>,
    slack_vector: ColumnVector<F>,
    commitment_hidings: Vec<F>,
}

impl<F: PrimeField> RelaxedPLONKWitness<F> {
    /// Returns the i-th column of the PLONK witness or an error if index is out of bounds.
    pub fn witness_column(&self, column_index: usize) -> Result<ColumnVector<F>, SangriaError> {
        self.plonk_witness.column(column_index)
    }

    /// Returns the i-th row of the PLONK witness or an error if index is out of bounds.
    pub fn witness_row(&self, row_index: usize) -> Result<Vec<F>, SangriaError> {
        self.plonk_witness.row(row_index)
    }

    /// Returns the slack (or error) vector from the relaxed PLONK witness.
    pub fn slack_vector(&self) -> Vec<F> {
        self.slack_vector.clone()
    }

    /// Returns the random values used when committing to the witness columns.
    pub fn hiding_randomnesses(&self) -> Vec<F> {
        self.commitment_hidings.clone()
    }

    /// Returns a column from the witness as well as the randomness used to commit to it or an error if index is out of bounds.
    pub fn witness_column_with_rand(
        &self,
        column_index: usize,
    ) -> Result<(ColumnVector<F>, F), SangriaError> {
        let column = self.plonk_witness.column(column_index)?;
        Ok((column, self.commitment_hidings[column_index]))
    }
}

/// A PLONK witness, this is a sub-table of the Trace with one row per circuit gate.
pub struct PLONKWitness<F: PrimeField> {
    matrix: Vec<ColumnVector<F>>,
}

impl<F: PrimeField> PLONKWitness<F> {
    pub fn column(&self, column_index: usize) -> Result<ColumnVector<F>, SangriaError> {
        if column_index > self.matrix.len() {
            return Err(SangriaError::IndexOutOfBounds);
        }

        Ok(self.matrix[column_index].clone())
    }

    pub fn row(&self, row_index: usize) -> Result<Vec<F>, SangriaError> {
        self.matrix
            .iter()
            .map(|column| -> Result<F, SangriaError> {
                if row_index > column.len() {
                    return Err(SangriaError::IndexOutOfBounds);
                }

                Ok(column[row_index])
            })
            .collect::<Result<Vec<_>, SangriaError>>()
    }
}

/// A PLONK instance, this is a sub-table of the Trace with one row per public input plus
/// one extra row to check the final output.
#[derive(Clone)]
pub struct PLONKInstance<F: PrimeField> {
    matrix: Vec<ColumnVector<F>>,
}

impl<F: PrimeField> PLONKInstance<F> {
    pub fn column(&self, column_index: usize) -> Result<ColumnVector<F>, SangriaError> {
        if column_index > self.matrix.len() {
            return Err(SangriaError::IndexOutOfBounds);
        }

        Ok(self.matrix[column_index].clone())
    }

    pub fn row(&self, row_index: usize) -> Result<Vec<F>, SangriaError> {
        self.matrix
            .iter()
            .map(|column| -> Result<F, SangriaError> {
                if row_index > column.len() {
                    return Err(SangriaError::IndexOutOfBounds);
                }

                Ok(column[row_index])
            })
            .collect::<Result<Vec<_>, SangriaError>>()
    }
}

/// A structure that hold the defining elements of a PLONK circuit
#[derive(Clone)]
pub struct PLONKCircuit<F: Field> {
    selectors: Vec<ColumnVector<F>>,
    copy_constraint: Permutation<F>,
}

impl<F: Field> PLONKCircuit<F> {
    /// Returns the selectors matrix.
    pub fn selectors(&self) -> Vec<ColumnVector<F>> {
        self.selectors.clone()
    }

    /// Returns a single selector or an error if index is out of bounds.
    pub fn single_selector(&self, selector_index: usize) -> Result<ColumnVector<F>, SangriaError> {
        if selector_index > self.selectors.len() {
            return Err(SangriaError::IndexOutOfBounds);
        }

        Ok(self.selectors[selector_index].clone())
    }

    /// Returns the copy constraints.
    pub fn copy_constraint(&self) -> Permutation<F> {
        self.copy_constraint.clone()
    }
}

impl<CircuitField: PrimeField> Absorb for PLONKCircuit<CircuitField> {
    fn to_sponge_bytes(&self, _dest: &mut Vec<u8>) {
        todo!()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, _dest: &mut Vec<F>) {
        todo!()
    }
}
