/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Converts an enum to an object
 */
export const convertEnumToObj = (enumType: any): any =>
  Object.keys(enumType)
    .filter((key) => isNaN(Number(key)))
    .reduce((previousValue: any, key: any) => {
      return { ...previousValue, [key]: enumType[key] };
    }, {});

/**
 * Converts an enum to an object but where the object is a reverse
 * map of the enumeration e.g [ key: value ] becomes [value: key]
 */
export const convertEnumToReverseMapObj = (enumType: any): any =>
  Object.keys(enumType)
    .filter((key) => isNaN(Number(key)))
    .reduce((previousValue: any, key: any) => {
      return { ...previousValue, [enumType[key]]: key };
    }, {});
