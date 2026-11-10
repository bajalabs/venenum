import "fastify";

declare module "fastify" {
  interface FastifyRequest {
    /** The exact bytes of the request body, which the signature covers. */
    rawBody?: Buffer;
    /** The caller whose signature was accepted. */
    caller?: string;
  }
}
