
export interface PasswordValidationResult {
  isValid: boolean;
  message: string | null; // General message if invalid, or null if valid
  errors: string[]; // List of specific unmet criteria
}

const MIN_LENGTH = 8;
const REGEX_UPPERCASE = /[A-Z]/;
const REGEX_LOWERCASE = /[a-z]/;
const REGEX_NUMBER = /[0-9]/;
// Common special characters.
const REGEX_SPECIAL = /[!@#$%^&*(),.?":{}|<>~`_+\-=\[\]\\';\/]/;

export function validatePassword(password: string): PasswordValidationResult {
  const errors: string[] = [];

  if (password.length < MIN_LENGTH) {
    errors.push(`Password must be at least ${MIN_LENGTH} characters long.`);
  }
  if (!REGEX_UPPERCASE.test(password)) {
    errors.push("Password must contain at least one uppercase letter (A-Z).");
  }
  if (!REGEX_LOWERCASE.test(password)) {
    errors.push("Password must contain at least one lowercase letter (a-z).");
  }
  if (!REGEX_NUMBER.test(password)) {
    errors.push("Password must contain at least one number (0-9).");
  }
  if (!REGEX_SPECIAL.test(password)) {
    errors.push("Password must contain at least one special character (e.g., !@#$%^&*).");
  }

  const isValid = errors.length === 0;
  return {
    isValid,
    message: isValid ? null : "Password does not meet all security requirements. Please check the errors listed above.",
    errors,
  };
}
