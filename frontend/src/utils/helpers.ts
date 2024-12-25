export const sanitizeString = (input: string): string => {
  if (!input) return "";

  // Remove HTML tags using a bounded quantifier
  let sanitized = input.replace(/<[^>]{0,1000}>/g, "");
  // Remove script tags using multiple passes with simpler patterns
  sanitized = sanitized.replace(/<script[^>]*>/gi, "");
  sanitized = sanitized.replace(/<\/script>/gi, "");

  // Allow alphanumeric, spaces, and basic punctuation
  sanitized = sanitized.replace(/[^a-zA-Z0-9\s.,!?-]/g, "");
  return sanitized.trim();
};
