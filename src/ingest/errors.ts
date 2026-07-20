/** Raised when an input cannot be understood. Never thrown for *non-compliance*. */
export class IngestError extends Error {
  readonly source: string;

  constructor(source: string, message: string) {
    super(`${source}: ${message}`);
    this.name = "IngestError";
    this.source = source;
  }
}
