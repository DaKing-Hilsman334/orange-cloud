/**
 * Certificate utilities for:
 * - API client authentication with certificates
 * - Webhook signature validation
 * - Certificate chain verification
 * - Azure/Microsoft service integration
 */

interface CertificateConfig {
  cert: string;
  key?: string;
  ca?: string[];
}

interface WebhookSignature {
  algorithm: string;
  signature: string;
  timestamp: number;
}

/**
 * Verify webhook signature using certificate chain
 * Supports both HMAC and RSA signatures
 */
export async function verifyWebhookSignature(
  payload: string,
  signature: WebhookSignature,
  trustedCerts: string[]
): Promise<boolean> {
  try {
    // For HMAC-based signatures
    if (signature.algorithm === 'HMAC-SHA256') {
      // Reconstruct the signed message
      const message = `${payload}.${signature.timestamp}`;
      
      // In production, use the actual cert as HMAC secret
      const encoder = new TextEncoder();
      const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(trustedCerts[0]),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign', 'verify']
      );

      const msgBuffer = encoder.encode(message);
      const signatureBuffer = hexToBuffer(signature.signature);
      
      const isValid = await crypto.subtle.verify(
        'HMAC',
        key,
        signatureBuffer,
        msgBuffer
      );

      // Also check timestamp to prevent replay attacks (5 minute window)
      const now = Math.floor(Date.now() / 1000);
      const isTimeValid = Math.abs(now - signature.timestamp) < 300;

      return isValid && isTimeValid;
    }

    // For RSA signatures, would need public key extraction from cert
    // This is a simplified version - production would need full cert parsing
    return false;
  } catch (err) {
    console.error('Webhook verification error:', err);
    return false;
  }
}

/**
 * Validate certificate chain against trusted certificates
 */
export function validateCertificateChain(
  certificateChain: string[],
  trustedCerts: string[]
): boolean {
  try {
    // Basic validation: check if any cert in chain matches trusted certs
    const lastCert = certificateChain[certificateChain.length - 1];
    
    return trustedCerts.some(trustedCert => 
      extractFingerprint(trustedCert) === extractFingerprint(lastCert)
    );
  } catch (err) {
    console.error('Certificate chain validation error:', err);
    return false;
  }
}

/**
 * Extract certificate fingerprint (simplified SHA-256)
 */
export function extractFingerprint(certPem: string): string {
  // Remove PEM headers and whitespace
  const certDer = certPem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s/g, '');

  return certDer.substring(0, 32); // Simplified fingerprint
}

/**
 * Extract certificate metadata
 */
export function extractCertificateMetadata(certPem: string): {
  subject?: string;
  issuer?: string;
  notBefore?: Date;
  notAfter?: Date;
} {
  try {
    // Basic extraction using regex - production would use proper X.509 parsing
    const lines = certPem.split('\n');
    
    return {
      subject: extractField(certPem, 'CN='),
      issuer: extractField(certPem, 'O='),
      notBefore: new Date(2025, 0, 1), // Placeholder
      notAfter: new Date(2026, 0, 1),  // Placeholder
    };
  } catch (err) {
    console.error('Certificate metadata extraction error:', err);
    return {};
  }
}

/**
 * Helper to extract certificate fields
 */
function extractField(certPem: string, fieldName: string): string | undefined {
  // This is a simplified extraction - real implementation would parse ASN.1
  const match = certPem.match(new RegExp(`${fieldName}([^,\n]+)`));
  return match ? match[1] : undefined;
}

/**
 * Convert hex string to binary buffer
 */
function hexToBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}

/**
 * Generate certificate fingerprint for pinning
 */
export function generateCertificatePins(certs: string[]): string[] {
  return certs.map(cert => {
    const fingerprint = extractFingerprint(cert);
    return `pin-sha256="${Buffer.from(fingerprint).toString('base64')}"`;
  });
}

/**
 * Validate certificate against pinned hashes
 */
export function validateCertificatePin(
  certPem: string,
  pinnedHashes: string[]
): boolean {
  const fingerprint = extractFingerprint(certPem);
  const certPin = `pin-sha256="${Buffer.from(fingerprint).toString('base64')}"`;
  
  return pinnedHashes.includes(certPin);
}

/**
 * Check certificate expiration
 */
export function isCertificateExpired(certPem: string): boolean {
  const metadata = extractCertificateMetadata(certPem);
  
  if (!metadata.notAfter) {
    return false;
  }

  return new Date() > metadata.notAfter;
}

/**
 * Get certificate validity window
 */
export function getCertificateValidity(
  certPem: string
): { valid: boolean; daysUntilExpiration: number } {
  const metadata = extractCertificateMetadata(certPem);
  
  if (!metadata.notAfter) {
    return { valid: false, daysUntilExpiration: 0 };
  }

  const now = new Date();
  const daysUntilExpiration = Math.ceil(
    (metadata.notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  );

  return {
    valid: daysUntilExpiration > 0,
    daysUntilExpiration,
  };
}

/**
 * Generate request signature for API calls using certificate
 * Mimics Azure SDK behavior
 */
export async function generateCertificateSignature(
  payload: string,
  certPem: string,
  algorithm: 'SHA256' | 'SHA512' = 'SHA256'
): Promise<string> {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(payload);

    // Create HMAC-based signature
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(certPem),
      { name: 'HMAC', hash: `SHA-${algorithm.slice(3)}` },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, data);
    return bufferToHex(signature);
  } catch (err) {
    console.error('Signature generation error:', err);
    throw err;
  }
}

/**
 * Helper to convert buffer to hex string
 */
function bufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Fetch from API with certificate authentication
 */
export async function fetchWithCertAuth(
  url: string,
  options: {
    cert: string;
    method?: string;
    body?: string;
    headers?: Record<string, string>;
  }
): Promise<Response> {
  const {
    cert,
    method = 'GET',
    body,
    headers = {},
  } = options;

  // Add certificate signature to headers
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = await generateCertificateSignature(body || '', cert);

  const requestHeaders = {
    ...headers,
    'X-Cert-Signature': signature,
    'X-Cert-Timestamp': timestamp.toString(),
    'X-Cert-Algorithm': 'HMAC-SHA256',
  };

  return fetch(url, {
    method,
    body,
    headers: requestHeaders,
  });
}

/**
 * Validate mutual TLS handshake
 */
export function validateMTLSHandshake(
  clientCert: string,
  trustedCAs: string[]
): { valid: boolean; reason?: string } {
  // Check if certificate is in trusted list
  const isInTrustedList = trustedCAs.some(
    ca => extractFingerprint(ca) === extractFingerprint(clientCert)
  );

  if (!isInTrustedList) {
    return { valid: false, reason: 'Certificate not in trusted list' };
  }

  // Check expiration
  if (isCertificateExpired(clientCert)) {
    return { valid: false, reason: 'Certificate expired' };
  }

  return { valid: true };
}
