/**
 * Minimal ambient declaration for `snarkjs` (it ships no type declarations).
 * The gate only needs Groth16 off-chain verification; the prover side uses
 * fullProve. Faithful to snarkjs 0.7.x.
 */
declare module "snarkjs" {
  export const groth16: {
    verify(vk: unknown, publicSignals: string[], proof: unknown): Promise<boolean>;
    fullProve(
      input: unknown,
      wasmPath: string,
      zkeyPath: string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
  };
}
