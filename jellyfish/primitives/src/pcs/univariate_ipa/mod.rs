use core::borrow::Borrow;
use core::marker::PhantomData;

use ark_ec::AffineCurve;
use ark_ff::{Field, One};
use ark_poly::{univariate::DensePolynomial, Polynomial};
use ark_poly_commit::{
    ipa_pc, LabeledCommitment, LabeledPolynomial, PCCommitment, PolynomialCommitment, PCRandomness,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::{
    rand::{CryptoRng, RngCore},
    string::String,
};
use blake2::Blake2s;
use jf_utils::Vec;

use super::{prelude::PCSError, CommitmentGroup, PolynomialCommitmentScheme, WithMaxDegree};

#[derive(Debug)]
pub struct UnivariateIPA<E: CommitmentGroup> {
    phantom: PhantomData<E>,
}

fn to_labeled<F: Field>(poly: &DensePolynomial<F>) -> LabeledPolynomial<F, DensePolynomial<F>> {
    LabeledPolynomial::new(String::from(""), poly.clone(), None, None)
}

fn to_labeled_cm<C: PCCommitment>(cm: &C) -> LabeledCommitment<C> {
    LabeledCommitment::new(String::from(""), cm.clone(), None)
}

/// The `ProverParams` type is identical to arkwork's `CommitKey` type but has an implementation of Eq as required
/// by the Jellyfish `PolynomialCommitmentScheme` trait.
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverParam<G: AffineCurve> {
    /// The key used to commit to polynomials.
    pub comm_key: Vec<G>,

    /// A random group generator.
    pub h: G,

    /// A random group generator that is to be used to make
    /// a commitment hiding.
    pub s: G,

    /// The maximum degree supported by the parameters
    /// this key was derived from.
    pub max_degree: usize,
}

impl<G: AffineCurve> From<ipa_pc::CommitterKey<G>> for ProverParam<G> {
    fn from(arkworks_commit_key: ipa_pc::CommitterKey<G>) -> Self {
        Self {
            comm_key: arkworks_commit_key.comm_key,
            h: arkworks_commit_key.h,
            s: arkworks_commit_key.s,
            max_degree: arkworks_commit_key.max_degree,
        }
    }
}

impl<G: AffineCurve> Into<ipa_pc::CommitterKey<G>> for &ProverParam<G> {
    fn into(self) -> ipa_pc::CommitterKey<G> {
        ipa_pc::CommitterKey {
            comm_key: self.comm_key.clone(),
            h: self.h,
            s: self.h,
            max_degree: self.max_degree,
        }
    }
}

pub type VerifierParam<G> = ProverParam<G>;

/// The `Proof` type is identical to arkwork's `ipa_pc::Proof` type but has an implementation of Eq as required
/// by the Jellyfish `PolynomialCommitmentScheme` trait.
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<G: AffineCurve> {
    /// Vector of left elements for each of the log_d iterations in `open`
    pub l_vec: Vec<G>,

    /// Vector of right elements for each of the log_d iterations within `open`
    pub r_vec: Vec<G>,

    /// Committer key from the last iteration within `open`
    pub final_comm_key: G,

    /// Coefficient from the last iteration within `open`
    pub c: G::ScalarField,

    /// Commitment to the blinding polynomial.
    pub hiding_comm: Option<G>,

    /// Linear combination of all the randomness used for commitments
    /// to the opened polynomials, along with the randomness used for the
    /// commitment to the hiding polynomial.
    pub rand: Option<G::ScalarField>,
}

impl<G: AffineCurve> From<ipa_pc::Proof<G>> for Proof<G> {
    fn from(arkworks_proof: ipa_pc::Proof<G>) -> Self {
        Self {
            l_vec: arkworks_proof.l_vec,
            r_vec: arkworks_proof.r_vec,
            final_comm_key: arkworks_proof.final_comm_key,
            c: arkworks_proof.c,
            hiding_comm: arkworks_proof.hiding_comm,
            rand: arkworks_proof.rand,
        }
    }
}

impl<G: AffineCurve> Into<ipa_pc::Proof<G>> for &Proof<G> {
    fn into(self) -> ipa_pc::Proof<G> {
        ipa_pc::Proof {
            l_vec: self.l_vec.clone(),
            r_vec: self.r_vec.clone(),
            final_comm_key: self.final_comm_key,
            c: self.c,
            hiding_comm: self.hiding_comm,
            rand: self.rand,
        }
    }
}

impl<E: CommitmentGroup> PolynomialCommitmentScheme<E> for UnivariateIPA<E> {
    type SRS = ipa_pc::UniversalParams<E::G1Affine>;
    type Point = E::Fr;
    type Polynomial = DensePolynomial<E::Fr>;
    type ProverParam = ProverParam<E::G1Affine>;
    type VerifierParam = VerifierParam<E::G1Affine>;
    type Evaluation = E::Fr;
    type Commitment = ipa_pc::Commitment<E::G1Affine>;
    type Proof = Proof<E::G1Affine>;
    type BatchCommitment = Vec<Self::Commitment>;
    type BatchProof = Vec<Self::Proof>;

    fn gen_srs_for_testing<R: RngCore + CryptoRng>(
        rng: &mut R,
        supported_size: usize,
    ) -> Result<Self::SRS, PCSError> {
        let arkworks_srs =
            ipa_pc::InnerProductArgPC::<E::G1Affine, Blake2s, DensePolynomial<E::Fr>>::setup(
                supported_size,
                None,
                rng,
            )?;

        Ok(arkworks_srs)
    }

    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_degree: usize,
        _supported_num_vars: Option<usize>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), super::prelude::PCSError> {
        let (arkworks_ck, arkworks_vk) = ipa_pc::InnerProductArgPC::<
            E::G1Affine,
            Blake2s,
            DensePolynomial<E::Fr>,
        >::trim(srs.borrow(), supported_degree, 0, None)?;

        Ok((arkworks_ck.into(), arkworks_vk.into()))
    }

    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, super::prelude::PCSError> {
        let arkworks_commitment =
            ipa_pc::InnerProductArgPC::<E::G1Affine, Blake2s, DensePolynomial<E::Fr>>::commit(
                &prover_param.borrow().into(),
                &[to_labeled(poly)],
                None,
            )?;

        Ok(arkworks_commitment.0[0].commitment().clone())
    }

    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), super::prelude::PCSError> {
        let evaluation = polynomial.evaluate(point);

        let commitment = Self::commit(prover_param.borrow(), polynomial)?;

        let arkworks_opening_proof =
            ipa_pc::InnerProductArgPC::<E::G1Affine, Blake2s, DensePolynomial<E::Fr>>::open(
                &prover_param.borrow().into(),
                &[to_labeled(polynomial)],
                &[to_labeled_cm(&commitment)],
                point,
                E::Fr::one(),
                &[ipa_pc::Randomness::empty()],
                None,
            )?;

        Ok((arkworks_opening_proof.into(), evaluation))
    }

    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &<E as CommitmentGroup>::Fr,
        proof: &Self::Proof,
    ) -> Result<bool, super::prelude::PCSError> {
        let arkworks_proof = proof.into();

        let res = ipa_pc::InnerProductArgPC::<E::G1Affine, Blake2s, DensePolynomial<E::Fr>>::check(
            &verifier_param.borrow().into(),
            &[to_labeled_cm(commitment)],
            point,
            [*value],
            &arkworks_proof,
            E::Fr::one(),
            None,
        )?;

        Ok(res)
    }

    fn batch_commit(
        _prover_param: impl Borrow<Self::ProverParam>,
        _polys: &[Self::Polynomial],
    ) -> Result<Self::BatchCommitment, super::prelude::PCSError> {
        todo!()
    }

    fn batch_open(
        _prover_param: impl Borrow<Self::ProverParam>,
        _batch_commitment: &Self::BatchCommitment,
        _polynomials: &[Self::Polynomial],
        _points: &[Self::Point],
    ) -> Result<(Self::BatchProof, Vec<Self::Evaluation>), super::prelude::PCSError> {
        todo!()
    }

    fn batch_verify<R: RngCore + CryptoRng>(
        _verifier_param: &Self::VerifierParam,
        _multi_commitment: &Self::BatchCommitment,
        _points: &[Self::Point],
        _values: &[<E as CommitmentGroup>::Fr],
        _batch_proof: &Self::BatchProof,
        _rng: &mut R,
    ) -> Result<bool, super::prelude::PCSError> {
        todo!()
    }
}

impl<G: AffineCurve> WithMaxDegree for ipa_pc::UniversalParams<G> {
    fn max_degree(&self) -> usize {
        self.comm_key.len() - 1
    }
}

#[cfg(test)]
#[allow(unused)]
mod tests {
    use std::println;

    use ark_bls12_377::Bls12_377;
    use ark_ff::UniformRand;
    use ark_poly::{univariate::DensePolynomial, UVPolynomial};
    use ark_poly_commit::{ipa_pc, LabeledPolynomial, PolynomialCommitment};
    use ark_std::{string::String, test_rng, vec};
    use blake2::Blake2s;

    use crate::pcs::PolynomialCommitmentScheme;

    use super::UnivariateIPA;

    type IPA = UnivariateIPA<Bls12_377>;
    type ArkworksIPA = ipa_pc::InnerProductArgPC<
        ark_bls12_377::G1Affine,
        Blake2s,
        DensePolynomial<ark_bls12_377::Fr>,
    >;

    #[test]
    fn test_crs_generation_and_trim() {
        let mut rng = test_rng();

        let max_degree = 10;
        let supported_degree = 8;

        let crs = IPA::gen_srs_for_testing(&mut rng, max_degree).unwrap();
        let (pk, vk) = IPA::trim(crs.clone(), supported_degree, None).unwrap();

        let arkworks_crs = ArkworksIPA::setup(max_degree, Some(1), &mut rng).unwrap();

        assert_eq!(arkworks_crs.comm_key, crs.comm_key);
        assert_eq!(arkworks_crs.h, crs.h);
        assert_eq!(arkworks_crs.s, arkworks_crs.s);

        let (arkworks_pk, arkworks_vk) =
            ArkworksIPA::trim(&arkworks_crs, supported_degree, 0, None).unwrap();

        assert_eq!(arkworks_pk.comm_key, pk.comm_key);
        assert_eq!(arkworks_pk.h, pk.h);
        assert_eq!(arkworks_pk.s, pk.s);
        assert_eq!(arkworks_pk.max_degree, pk.max_degree);

        assert_eq!(arkworks_vk.comm_key, vk.comm_key);
        assert_eq!(arkworks_vk.h, vk.h);
        assert_eq!(arkworks_vk.s, vk.s);
        assert_eq!(arkworks_vk.max_degree, vk.max_degree);
    }

    #[test]
    fn test_commit_and_open() {
        let mut rng = test_rng();

        let max_degree = 10;
        let supported_degree = 8;

        let crs = IPA::gen_srs_for_testing(&mut rng, max_degree).unwrap();

        let (pk, vk) = IPA::trim(crs, supported_degree, None).unwrap();

        let polynomial = DensePolynomial::<ark_bls12_377::Fr>::rand(supported_degree, &mut rng);

        let commitment = IPA::commit(&pk, &polynomial).unwrap();

        let eval_point = ark_bls12_377::Fr::rand(&mut rng);
        let (opening_proof, eval) = IPA::open(&pk, &polynomial, &eval_point).unwrap();

        let res = IPA::verify(&vk, &commitment, &eval_point, &eval, &opening_proof).unwrap();

        assert!(res)
    }
}
