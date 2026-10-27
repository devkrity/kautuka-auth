export function hasDuplicateParameters(form) {
  const names = new Set();
  for (const [name] of form) {
    if (names.has(name)) return true;
    names.add(name);
  }
  return false;
}
