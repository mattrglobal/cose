/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

// Using a star import here instead of importing just cbor as the web package exports this
// way before bundling with webpack
import * as cbor from "cbor-web";
import { Tagged } from "cbor-web";

export default cbor;
export { Tagged };
