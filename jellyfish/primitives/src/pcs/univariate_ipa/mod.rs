use core::borrow::Borrow;
use core::marker::PhantomData;

use ark_ec::AffineCurve;
use ark_ff::{Field, One};
use ark_poly::{univariate::DensePolynomial, Polynomial};
use ark_poly_commit::{
    ipa_pc, LabeledCommitment, LabeledPolynomial, PCCommitment, PCRandomness, PolynomialCommitment,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::{
    rand::{CryptoRng, RngCore},
    string::String,
};
use blake2::Blake2s;
use jf_utils::Vec;

use super::{prelude::PCSError, CommitmentGroup, PolynomialCommitmentScheme, WithMaxDegree};

type ArkworksIPA<G> =
    ipa_pc::InnerProductArgPC<G, Blake2s, DensePolynomial<<G as AffineCurve>::ScalarField>>;

/// An inner-product argument polynomial commitment scheme. We wrap around the one provided by arkworks.
/// Note however that we do not enforce degree bounds as these are not required by the PLONK protocol (see Remark 4.2)
/// in the PLONK paper. We also do not allow for hiding commitments as we follow the Jellyfish PCS trait, see here <https://github.com/geometryresearch/sangria_impl/blob/ipa/jellyfish/primitives/src/pcs/mod.rs#L171-L172>
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

/// Like in the arkworks IPA< our verifier key is the same as the prover key.
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
        let arkworks_srs = ArkworksIPA::setup(supported_size, None, rng)?;

        Ok(arkworks_srs)
    }

    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_degree: usize,
        _supported_num_vars: Option<usize>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), super::prelude::PCSError> {
        let (arkworks_ck, arkworks_vk) =
            ArkworksIPA::trim(srs.borrow(), supported_degree, 0, None)?;

        Ok((arkworks_ck.into(), arkworks_vk.into()))
    }

    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, super::prelude::PCSError> {
        let arkworks_commitment =
            ArkworksIPA::commit(&prover_param.borrow().into(), &[to_labeled(poly)], None)?;

        Ok(arkworks_commitment.0[0].commitment().clone())
    }

    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), super::prelude::PCSError> {
        let evaluation = polynomial.evaluate(point);

        let commitment = Self::commit(prover_param.borrow(), polynomial)?; // an unfortunate artifact of arkworks, we *need* the commitment to produce an opening proof...

        let arkworks_opening_proof = ArkworksIPA::open(
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

        let res = ArkworksIPA::check(
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
        prover_param: impl Borrow<Self::ProverParam>,
        polys: &[Self::Polynomial],
    ) -> Result<Self::BatchCommitment, super::prelude::PCSError> {
        let labeled_polynomials: Vec<LabeledPolynomial<E::Fr, DensePolynomial<E::Fr>>> =
            polys.iter().map(|p| to_labeled(p)).collect();

        let (labeled_commitments, _batch_randomness) =
            ArkworksIPA::commit(&prover_param.borrow().into(), &labeled_polynomials, None)?;

        let commitments = labeled_commitments
            .iter()
            .map(|comm| comm.commitment().clone())
            .collect();

        Ok(commitments)
    }

    fn batch_open(
        prover_param: impl Borrow<Self::ProverParam>,
        batch_commitment: &Self::BatchCommitment,
        polynomials: &[Self::Polynomial],
        points: &[Self::Point],
    ) -> Result<(Self::BatchProof, Vec<Self::Evaluation>), super::prelude::PCSError> {
        let mut batch_proof: Self::BatchProof = Vec::new();
        let mut evals: Vec<E::Fr> = Vec::new();
        for ((polynomial, commitment), point) in polynomials
            .iter()
            .zip(batch_commitment.iter())
            .zip(points.iter())
        {
            let eval = polynomial.evaluate(point);

            let arkworks_opening_proof = ArkworksIPA::open(
                &prover_param.borrow().into(),
                &[to_labeled(polynomial)],
                &[to_labeled_cm(commitment)],
                point,
                E::Fr::one(),
                &[ipa_pc::Randomness::empty()],
                None,
            )?;

            evals.push(eval);
            batch_proof.push(arkworks_opening_proof.into())
        }

        Ok((batch_proof, evals))
    }

    // naive implementation, we verify each proof individually.
    fn batch_verify<R: RngCore + CryptoRng>(
        verifier_param: &Self::VerifierParam,
        multi_commitment: &Self::BatchCommitment,
        points: &[Self::Point],
        values: &[<E as CommitmentGroup>::Fr],
        batch_proof: &Self::BatchProof,
        _rng: &mut R,
    ) -> Result<bool, super::prelude::PCSError> {
        let mut batch_res = true;
        for (((commitment, point), value), proof) in multi_commitment
            .iter()
            .zip(points.iter())
            .zip(values.iter())
            .zip(batch_proof.iter())
        {
            let res = Self::verify(verifier_param, commitment, point, value, proof)?;
            if res == false {
                batch_res = false;
                return Ok(batch_res);
            }
        }

        Ok(batch_res)
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
    use ark_poly::{evaluations, univariate::DensePolynomial, UVPolynomial};
    use ark_poly_commit::{
        ipa_pc, Evaluations, LabeledPolynomial, PCRandomness, PolynomialCommitment, QuerySet,
    };
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

    #[test]
    fn test_batch_commit_and_open() {
        let mut rng = test_rng();

        let max_degree = 10;
        let supported_degree = 8;

        let crs = IPA::gen_srs_for_testing(&mut rng, max_degree).unwrap();

        let (pk, vk) = IPA::trim(crs, supported_degree, None).unwrap();

        let a = DensePolynomial::<ark_bls12_377::Fr>::rand(supported_degree, &mut rng);
        let b = DensePolynomial::<ark_bls12_377::Fr>::rand(supported_degree, &mut rng);
        let c = DensePolynomial::<ark_bls12_377::Fr>::rand(supported_degree, &mut rng);

        let polynomials = vec![a, b, c];

        let batch_commitment = IPA::batch_commit(&pk, &polynomials).unwrap();

        let evaluation_point_a = ark_bls12_377::Fr::rand(&mut rng);
        let evaluation_point_b = ark_bls12_377::Fr::rand(&mut rng);
        let evaluation_point_c = ark_bls12_377::Fr::rand(&mut rng);
        let evaluation_points = vec![evaluation_point_a, evaluation_point_b, evaluation_point_c];

        let (batch_proof, evaluations) =
            IPA::batch_open(&pk, &batch_commitment, &polynomials, &evaluation_points).unwrap();

        let batch_res = IPA::batch_verify(
            &vk,
            &batch_commitment,
            &evaluation_points,
            &evaluations,
            &batch_proof,
            &mut rng,
        )
        .unwrap();

        assert!(batch_res)
    }

    #[ignore]
    #[test]
    /**
    Some notes (Nico):
    Arkworks uses the `QuerySet`/`Evaluations` maps to keep track of which polynomial is evaluated at what point. We can
    achieve a similar result by enforcing a strict ordering of polynomials and points.

    On the other hand, Arkworks uses an opening challenge that must be provided by the verifier (interactive) or random oracle
    (fiat-shamir). We can also achieve this by having our IPA work over a generic RandomOracle/Digest type.
    */
    fn test_arkworks_batch() {
        let mut rng = test_rng();

        let max_degree = 10;
        let supported_degree = 8;

        let a = DensePolynomial::<ark_bls12_377::Fr>::rand(supported_degree, &mut rng);
        let a = LabeledPolynomial::new(String::from("a"), a, None, None);

        let b = DensePolynomial::<ark_bls12_377::Fr>::rand(supported_degree, &mut rng);
        let b = LabeledPolynomial::new(String::from("b"), b, None, None);

        let c = DensePolynomial::<ark_bls12_377::Fr>::rand(supported_degree, &mut rng);
        let c = LabeledPolynomial::new(String::from("c"), c, None, None);

        let polynomials = vec![a.clone(), b.clone(), c.clone()];

        let crs = ArkworksIPA::setup(max_degree, Some(1), &mut rng).unwrap();

        let (pk, vk) = ArkworksIPA::trim(&crs, supported_degree, 0, None).unwrap();

        let (commitments, randomnesses) = ArkworksIPA::commit(&pk, &polynomials, None).unwrap();

        let new_rands = vec![ipa_pc::Randomness::<ark_bls12_377::G1Affine>::empty(); 3]; // replace the randomness with empty randomness to make sure that we are not using hiding commitments,

        let evaluation_point_a = ark_bls12_377::Fr::rand(&mut rng);
        let evaluation_point_b = ark_bls12_377::Fr::rand(&mut rng);
        let evaluation_point_c = ark_bls12_377::Fr::rand(&mut rng);
        let mut evaluations = Evaluations::new();
        evaluations.insert(
            (String::from("a"), evaluation_point_a),
            a.evaluate(&evaluation_point_a),
        );
        evaluations.insert(
            (String::from("b"), evaluation_point_b),
            b.evaluate(&evaluation_point_b),
        );
        evaluations.insert(
            (String::from("c"), evaluation_point_c),
            c.evaluate(&evaluation_point_c),
        );

        let mut query_set = QuerySet::new();
        query_set.insert((
            String::from("a"),
            (String::from("evaluation_point_a"), evaluation_point_a),
        ));
        query_set.insert((
            String::from("b"),
            (String::from("evaluation_point_b"), evaluation_point_b),
        ));
        query_set.insert((
            String::from("c"),
            (String::from("evaluation_point_c"), evaluation_point_c),
        ));

        let opening_challenge = ark_bls12_377::Fr::rand(&mut rng);

        let batch_proof = ArkworksIPA::batch_open(
            &pk,
            &polynomials,
            &commitments,
            &query_set,
            opening_challenge,
            &new_rands,
            None,
        )
        .unwrap();

        let res = ArkworksIPA::batch_check(
            &vk,
            &commitments,
            &query_set,
            &evaluations,
            &batch_proof,
            opening_challenge,
            &mut rng,
        )
        .unwrap();

        assert!(res)
    }
}
