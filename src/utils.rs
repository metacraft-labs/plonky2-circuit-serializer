use std::{fs, marker::PhantomData, time::Instant};

use crate::serializer::{
    CustomGateSerializer, CustomGeneratorSerializer, CustomGeneratorSerializerOuter,
};
use multithreaded_fs::{process_file_bytes, read_file, types::ByteHandler};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::{
            CircuitData, CommonCircuitData, ProverOnlyCircuitData, VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig, Hasher},
    },
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Data {
    bytes: Vec<u8>,
}

impl ByteHandler for Data {
    fn get_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(a: Vec<u8>) -> Self {
        Data { bytes: a }
    }
}

pub fn dump_bytes_to_json(bytes: Vec<u8>, json_path: &str) {
    // Serialize Vec<u8> to json
    let serialized_data = serde_json::to_string(&Data {
        bytes: bytes.clone(),
    })
    .expect("Failed to serialize data");
    // Write json to file
    fs::write(json_path, serialized_data).expect("Failed to write to file");
}

pub fn dump_circuit_data<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    data: &CircuitData<F, C, D>,
    storage_dir: &str,
) where
    [(); C::Hasher::HASH_SIZE]:,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let cd_bytes = data.common.clone().to_bytes(&CustomGateSerializer).unwrap();
    dump_bytes_to_json(cd_bytes, format!("{storage_dir}/common_data.json").as_str());
    let prover_only_bytes = data
        .prover_only
        .to_bytes(
            &CustomGeneratorSerializer::<C, D> {
                _phantom: PhantomData::<C>,
            },
            &data.common,
        )
        .unwrap();
    dump_bytes_to_json(
        prover_only_bytes.clone(),
        format!("{storage_dir}/prover_only.json").as_str(),
    );
    process_file_bytes(
        &prover_only_bytes,
        String::from(storage_dir),
        32,
        String::from("prover_only"),
    );
    let verifier_only_bytes = data.verifier_only.to_bytes().unwrap();
    dump_bytes_to_json(
        verifier_only_bytes,
        format!("{storage_dir}/verifier_only.json").as_str(),
    );
}

pub fn dump_outer_circuit_data<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    data: &CircuitData<F, C, D>,
    storage_dir: &str,
) where
    C::Hasher: Hasher<F>,
{
    let cd_bytes = data.common.clone().to_bytes(&CustomGateSerializer).unwrap();
    dump_bytes_to_json(cd_bytes, format!("{storage_dir}/common_data.json").as_str());
    let prover_only_bytes = data
        .prover_only
        .to_bytes(
            &CustomGeneratorSerializerOuter::<C, D> {
                _phantom: PhantomData::<C>,
            },
            &data.common,
        )
        .unwrap();
    dump_bytes_to_json(
        prover_only_bytes,
        format!("{storage_dir}/prover_only.json").as_str(),
    );
    let verifier_only_bytes = data.verifier_only.to_bytes().unwrap();
    dump_bytes_to_json(
        verifier_only_bytes,
        format!("{storage_dir}/verifier_only.json").as_str(),
    );
}

pub fn read_bytes_from_json(json_path: &str) -> Vec<u8> {
    // Read json data
    let json_data = fs::read_to_string(json_path).expect("Failed to read from file");
    // Deserialize json back to Vec<u8>
    let deserialized_data: Data =
        serde_json::from_str(&json_data).expect("Failed to deserialize data");
    deserialized_data.bytes
}

pub fn folder_exists(folder_path: &str) -> bool {
    match fs::metadata(folder_path) {
        Ok(metadata) => metadata.is_dir(),
        Err(_) => false,
    }
}

fn read_prover_only_bytes(storage_dir: &str) -> Vec<u8> {
    let prover_only_path = format!("{}/prover_only", storage_dir);
    let prover_only_bytes: Vec<u8>;
    if folder_exists(&prover_only_path) {
        let data: Data = read_file::<Data>(String::from(storage_dir), String::from("prover_only"));
        prover_only_bytes = data.bytes;
    } else {
        prover_only_bytes =
            read_bytes_from_json(format!("{storage_dir}/prover_only.json").as_str());
    }
    prover_only_bytes
}
pub fn load_circuit_data_from_dir<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    storage_dir: &str,
) -> CircuitData<F, C, D>
where
    [(); C::Hasher::HASH_SIZE]:,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    println!("Reconstructing common data");
    let t_cd = Instant::now();
    let cd_bytes = read_bytes_from_json(format!("{storage_dir}/common_data.json").as_str());
    let common_data =
        CommonCircuitData::<F, D>::from_bytes(cd_bytes, &CustomGateSerializer).unwrap();
    println!("Common data reconstructed in {:?}", t_cd.elapsed());

    println!("Reconstructing prover only data");
    let t_po = Instant::now();
    let prover_only_bytes = read_prover_only_bytes(storage_dir);
    let prover_only = ProverOnlyCircuitData::<F, C, D>::from_bytes(
        prover_only_bytes.as_slice(),
        &CustomGeneratorSerializer::<C, D> {
            _phantom: PhantomData::<C>,
        },
        &common_data,
    )
    .unwrap();
    println!("Prover only data reconstructed in {:?}", t_po.elapsed());

    println!("Reconstructing verifier only data");
    let t_vo = Instant::now();
    let verifier_only_bytes =
        read_bytes_from_json(format!("{storage_dir}/verifier_only.json").as_str());
    let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_only_bytes).unwrap();
    println!("Verifier only data reconstructed in {:?}", t_vo.elapsed());

    CircuitData::<F, C, D> {
        prover_only,
        verifier_only,
        common: common_data,
    }
}

pub fn load_outer_circuit_data_from_dir<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    storage_dir: &str,
) -> CircuitData<F, C, D>
where
    C::Hasher: Hasher<F>,
{
    println!("Reconstructing common data");
    let t_cd = Instant::now();
    let cd_bytes = read_bytes_from_json(format!("{storage_dir}/common_data.json").as_str());
    let common_data =
        CommonCircuitData::<F, D>::from_bytes(cd_bytes, &CustomGateSerializer).unwrap();
    println!("Common data reconstructed in {:?}", t_cd.elapsed());

    println!("Reconstructing prover only data");
    let t_po = Instant::now();
    let prover_only_bytes =
        read_bytes_from_json(format!("{storage_dir}/prover_only.json").as_str());
    let prover_only = ProverOnlyCircuitData::<F, C, D>::from_bytes(
        prover_only_bytes.as_slice(),
        &CustomGeneratorSerializerOuter::<C, D> {
            _phantom: PhantomData::<C>,
        },
        &common_data,
    )
    .unwrap();
    println!("Prover only data reconstructed in {:?}", t_po.elapsed());

    println!("Reconstructing verifier only data");
    let t_vo = Instant::now();
    let verifier_only_bytes =
        read_bytes_from_json(format!("{storage_dir}/verifier_only.json").as_str());
    let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_only_bytes).unwrap();
    println!("Verifier only data reconstructed in {:?}", t_vo.elapsed());

    CircuitData::<F, C, D> {
        prover_only,
        verifier_only,
        common: common_data,
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use plonky2::plonk::prover::prove;
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn circut_dump_and_read_test() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // The arithmetic circuit x² - 4x + 7
        let x = builder.add_virtual_target();
        let a = builder.mul(x, x);
        let b = builder.mul_const(F::from_canonical_u32(4), x);
        let c = builder.mul_const(F::NEG_ONE, b);
        let d = builder.add(a, c);
        let e = builder.add_const(d, F::from_canonical_u32(7));

        // Public inputs are the initial value (provided below) and the result (which is generated).
        builder.register_public_input(x);
        builder.register_public_input(e);
        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u32(1));
        let data = builder.build::<C>();
        dump_circuit_data::<F, C, D>(&data, "./test");
        let data1 = load_circuit_data_from_dir::<F, C, D>("./test");
        let proof_with_pis = prove::<F, C, D>(
            &data1.prover_only,
            &data1.common,
            pw,
            &mut Default::default(),
        )
        .unwrap();
        data1.verify(proof_with_pis.clone()).expect("verify error");
    }
}
