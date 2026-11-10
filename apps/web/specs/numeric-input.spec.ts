import { normalizeNumericInput } from '../app/_lib/numeric-input';

describe('numeric input boundary', () => {
  it.each([
    ['0123456789', '0123456789'],
    ['\u06f0\u06f1\u06f2\u06f3\u06f4\u06f5\u06f6\u06f7\u06f8\u06f9', '0123456789'],
    ['\u0660\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668\u0669', '0123456789'],
    ['0\u06f1\u066234\u06f5', '012345'],
    ['+\u06f9\u06689\u06f1\u06623456789', '+989123456789'],
    ['', ''],
  ])('converts supported ranges without numeric coercion', (input, expected) => {
    expect(normalizeNumericInput(input)).toBe(expected);
    expect(normalizeNumericInput(expected)).toBe(expected);
  });

  it.each(['\uff10\uff11\uff12\uff13\uff14\uff15', ' 012345 ', '01-2345', '012345x', '\u202e012345', '012345\u2069']) (
    'does not normalize or strip unsupported characters', (value) => {
      expect(normalizeNumericInput(value)).toBe(value);
    }
  );
});
