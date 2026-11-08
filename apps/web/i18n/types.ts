export type CatalogShape<T> = {
  -readonly [Key in keyof T]: T[Key] extends string ? string : CatalogShape<T[Key]>;
};

// Preserve ICU literal inference while allowing either trusted translation at
// each leaf, including an English leaf supplied by the fallback merge.
export type LocalizedCatalog<Base, Translation> = {
  [Key in keyof Base]: Base[Key] extends string
    ? Base[Key] | (Key extends keyof Translation ? Translation[Key] : never)
    : LocalizedCatalog<Base[Key], Key extends keyof Translation ? Translation[Key] : never>;
};

export type MessageKeys<T> = {
  [Key in keyof T & string]: T[Key] extends string ? Key : `${Key}.${MessageKeys<T[Key]>}`;
}[keyof T & string];
