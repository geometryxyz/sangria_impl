use ark_ff::PrimeField;
use proof_essentials::vector_commitment::HomomorphicCommitmentScheme;

use crate::{folding_scheme::FoldingCommitmentConfig, SangriaError};

type ColumnVector<F> = Vec<F>;

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
pub struct PLONKCircuit {}
