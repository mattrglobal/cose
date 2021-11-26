/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

export const getCurrentNodeMajorVersion = (): number | undefined => {
  const nodeMajorVersion = /^v(\d+)/.exec(process.version)?.[1];
  return nodeMajorVersion ? parseInt(nodeMajorVersion, 10) : undefined;
};
