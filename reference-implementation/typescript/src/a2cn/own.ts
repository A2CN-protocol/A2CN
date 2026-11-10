/**
 * Own-property access for objects keyed by caller input.
 *
 * A plain object inherits names from Object.prototype (`constructor`,
 * `toString`, `__proto__`, ...), and assigning to `__proto__` replaces the
 * object's prototype instead of adding an entry. A Python dict has neither
 * behaviour, so every store or lookup whose key comes from a request, a record
 * or a caller reads and writes own properties only, through these helpers.
 */

/** Whether `obj` has `key` as an own property. */
export function hasOwn(obj: object, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/** The own property `key` of `obj`, or undefined when it has none. */
export function ownGet<T>(obj: Readonly<Record<string, T>>, key: string): T | undefined {
  return hasOwn(obj, key) ? obj[key] : undefined;
}

/**
 * Set `key` on `obj` as an own, enumerable data property, as a dict assignment
 * does. Unlike `obj[key] = value`, a key of `__proto__` adds an entry rather
 * than replacing the object's prototype.
 */
export function setOwn<T>(obj: Record<string, T>, key: string, value: NoInfer<T>): void {
  Object.defineProperty(obj, key, { value, writable: true, enumerable: true, configurable: true });
}
