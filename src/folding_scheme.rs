use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use proof_essentials::vector_commitment::HomomorphicCommitmentScheme;

use crate::{
    NonInteractiveFoldingScheme, PLONKCircuit, RelaxedPLONKInstance, RelaxedPLONKWitness,
    SangriaError,
};

/// A folding scheme for relaxed PLONK
pub struct PLONKFoldingScheme<
    F: PrimeField,
    CommS: HomomorphicCommitmentScheme<F>,
    CommW: HomomorphicCommitmentScheme<F>,
>(PhantomData<(F, CommS, CommW)>);

/// Public parameters for the folding scheme. Contains size parameters for the PLONK circuits
/// and commitment parameters for vectors of sizes `number_of_gates` and `number_of_public_inputs + number_of_gates + 1`
pub struct PublicParameters<
    F: PrimeField,
    CommS: HomomorphicCommitmentScheme<F>,
    CommW: HomomorphicCommitmentScheme<F>,
> {
    pub number_of_public_inputs: usize,
    pub number_of_gates: usize,
    pub commit_key_witness: CommW::CommitKey,
    pub commit_key_selectors_and_slack: CommS::CommitKey,
}

pub struct VerifierKey<F: PrimeField, CommS: HomomorphicCommitmentScheme<F>> {
    pub selector_c_commitment: CommS::Commitment,
}

pub struct ProverKey<
    F: PrimeField,
    CommS: HomomorphicCommitmentScheme<F>,
    CommW: HomomorphicCommitmentScheme<F>,
> {
    pub circuit: PLONKCircuit,
    pub public_parameters: PublicParameters<F, CommS, CommW>,
    pub verifier_key: VerifierKey<F, CommS>,
    pub selector_c_commit_randomness: F,
}

impl<F, CommS, CommW> NonInteractiveFoldingScheme for PLONKFoldingScheme<F, CommS, CommW>
where
    F: PrimeField,
    CommS: HomomorphicCommitmentScheme<F>,
    CommW: HomomorphicCommitmentScheme<F>,
{
    type PublicParameters = PublicParameters<F, CommS, CommW>;
    type Structure = PLONKCircuit;
    type Instance = RelaxedPLONKInstance;
    type Witness = RelaxedPLONKWitness;
    type ProverKey = ProverKey<F, CommS, CommW>;
    type VerifierKey = VerifierKey<F, CommS>;
    type ProverMessage = CommS::Commitment;

    fn setup<R: ark_std::rand::Rng>(rng: &mut R) -> Self::PublicParameters {
        todo!()
    }

    fn encode<R: ark_std::rand::Rng>(
        pp: &Self::PublicParameters,
        circuit: &Self::Structure,
        rng: &mut R,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), SangriaError> {
        todo!()
    }

    fn prover(
        prover_key: &Self::ProverKey,
        left_instance: &Self::Instance,
        left_witness: &Self::Witness,
        right_instance: &Self::Instance,
        right_witness: &Self::Witness,
    ) -> Result<(Self::Instance, Self::Witness, Self::ProverMessage), SangriaError> {
        todo!()
    }

    fn verifier(
        verifier_key: &Self::VerifierKey,
        left_instance: &Self::Instance,
        right_instance: &Self::Instance,
        prover_message: &Self::ProverMessage,
    ) -> Result<Self::Instance, SangriaError> {
        todo!()
    }
}
