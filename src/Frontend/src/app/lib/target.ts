/** El backend solo acepta IP o FQDN puros (sin esquema/ruta/puerto). */
export const normalizeTarget = (raw: string): string => {
  let value = raw.trim();
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(value)) {
    try {
      value = new URL(value).hostname;
    } catch {
      value = value.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '').split(/[/?#]/)[0];
    }
  } else {
    value = value.split(/[/?#]/)[0];
  }
  return value.split(':')[0];
};
