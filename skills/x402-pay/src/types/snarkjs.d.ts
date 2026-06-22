/**
 * Minimal ambient declaration for `snarkjs` (it ships no type declarations).
 * The prover side uses groth16.fullProve; the gate side uses groth16.verify.
 * Faithful to snarkjs 0.7.x.
 */
declare module "snarkjs" {
  export const groth16: {
    fullProve(
      input: unknown,
      wasmPath: string,
      zkeyPath: string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    verify(vk: unknown, publicSignals: string[], proof: unknown): Promise<boolean>;
  };
}
