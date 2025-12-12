// Frontend validation utilities
import { showValidationError } from "./toast";

/**
 * Validate domain name format
 */
export const validateDomain = (domain) => {
  if (!domain || typeof domain !== "string") {
    return { valid: false, error: "Domain cannot be empty" };
  }

  const trimmed = domain.trim();

  if (trimmed.length > 253) {
    return { valid: false, error: "Domain name too long (max 253 characters)" };
  }

  // Domain regex pattern
  const pattern =
    /^(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)*[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$/;

  if (!pattern.test(trimmed)) {
    return { valid: false, error: "Invalid domain format" };
  }

  return { valid: true, error: "" };
};

/**
 * Validate IP address (simple check)
 */
export const validateIP = (ip) => {
  if (!ip || typeof ip !== "string") {
    return { valid: false, error: "IP address cannot be empty" };
  }

  const trimmed = ip.trim();

  // Simple IPv4 regex
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;

  if (!ipv4Pattern.test(trimmed)) {
    return { valid: false, error: "Invalid IP address format" };
  }

  // Check octets are in valid range
  const octets = trimmed.split(".");
  for (const octet of octets) {
    const num = parseInt(octet, 10);
    if (num < 0 || num > 255) {
      return { valid: false, error: "Invalid IP address range" };
    }
  }

  return { valid: true, error: "" };
};

/**
 * Validate CIDR notation
 */
export const validateCIDR = (cidr) => {
  if (!cidr || typeof cidr !== "string") {
    return { valid: false, error: "CIDR notation cannot be empty" };
  }

  const trimmed = cidr.trim();

  // CIDR pattern: IP/mask
  const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

  if (!cidrPattern.test(trimmed)) {
    return {
      valid: false,
      error: "Invalid CIDR format (use IP/mask like 192.168.1.0/24)",
    };
  }

  const [ip, mask] = trimmed.split("/");

  // Validate IP part
  const ipValidation = validateIP(ip);
  if (!ipValidation.valid) {
    return ipValidation;
  }

  // Validate mask
  const maskNum = parseInt(mask, 10);
  if (maskNum < 0 || maskNum > 32) {
    return { valid: false, error: "Invalid CIDR mask (must be 0-32)" };
  }

  return { valid: true, error: "" };
};

/**
 * Validate campaign name
 */
export const validateCampaignName = (name) => {
  if (!name || typeof name !== "string") {
    return { valid: false, error: "Campaign name cannot be empty" };
  }

  const trimmed = name.trim();

  if (trimmed.length < 3) {
    return {
      valid: false,
      error: "Campaign name must be at least 3 characters",
    };
  }

  if (trimmed.length > 100) {
    return {
      valid: false,
      error: "Campaign name too long (max 100 characters)",
    };
  }

  // Allow alphanumeric, spaces, hyphens, underscores
  if (!/^[a-zA-Z0-9_ -]+$/.test(trimmed)) {
    return { valid: false, error: "Campaign name contains invalid characters" };
  }

  return { valid: true, error: "" };
};

/**
 * Validate target (domain, IP, or CIDR)
 */
export const validateTarget = (target) => {
  if (!target || typeof target !== "string") {
    return { valid: false, error: "Target cannot be empty" };
  }

  const trimmed = target.trim();

  // Try validating as each type
  const domainValidation = validateDomain(trimmed);
  if (domainValidation.valid) return domainValidation;

  const ipValidation = validateIP(trimmed);
  if (ipValidation.valid) return ipValidation;

  const cidrValidation = validateCIDR(trimmed);
  if (cidrValidation.valid) return cidrValidation;

  return {
    valid: false,
    error: "Must be a valid domain, IP address, or CIDR notation",
  };
};

/**
 * Validate email address
 */
export const validateEmail = (email) => {
  if (!email) {
    return { valid: true, error: "" }; // Email is optional
  }

  if (typeof email !== "string") {
    return { valid: false, error: "Invalid email format" };
  }

  const trimmed = email.trim();

  // Basic email regex
  const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

  if (!emailPattern.test(trimmed)) {
    return { valid: false, error: "Invalid email address format" };
  }

  return { valid: true, error: "" };
};

/**
 * Validate all campaign form data
 */
export const validateCampaignData = (formData) => {
  const errors = {};

  // Validate campaign name
  const nameValidation = validateCampaignName(formData.name);
  if (!nameValidation.valid) {
    errors.name = nameValidation.error;
  }

  // Validate domain
  const domainValidation = validateDomain(formData.domain);
  if (!domainValidation.valid) {
    errors.domain = domainValidation.error;
  }

  // Validate targets
  if (!formData.targets || !formData.targets.trim()) {
    errors.targets = "At least one target is required";
  } else {
    const targetList = formData.targets.split("\n").filter((t) => t.trim());
    for (let i = 0; i < targetList.length; i++) {
      const targetValidation = validateTarget(targetList[i]);
      if (!targetValidation.valid) {
        errors.targets = `Line ${i + 1}: ${targetValidation.error}`;
        break;
      }
    }
  }

  // Validate optional email
  if (formData.notification_email) {
    const emailValidation = validateEmail(formData.notification_email);
    if (!emailValidation.valid) {
      errors.notification_email = emailValidation.error;
    }
  }

  return {
    valid: Object.keys(errors).length === 0,
    errors,
  };
};
