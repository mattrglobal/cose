import { MultiSignDecodedResult } from "./MultiSignDecodedResult";
import { MultiSignOptions } from "./MultiSignOptions";
import { SignOptions } from "./SignOptions";
import { SingleSignDecodedResult } from "./SingleSignDecodedResult";
import { SingleSignOptions } from "./SingleSignOptions";

export type SignResult<T extends SignOptions> = T extends SingleSignOptions & { skipEncodingResult: true }
  ? SingleSignDecodedResult
  : T extends MultiSignOptions & { skipEncodingResult: true }
  ? MultiSignDecodedResult
  : Uint8Array;
