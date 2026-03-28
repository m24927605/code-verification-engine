const secret = process.env.JWT_SECRET;

export const JWT_SECRET = secret ?? "local-fallback";
