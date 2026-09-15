/**
 * Webhook utilities for secure event delivery
 * - Generate webhook signatures
 * - Validate incoming webhooks
 * - Retry failed deliveries
 * - Manage webhook subscriptions
 */

export interface WebhookEvent {
  id: string;
  type: 'upload' | 'download' | 'delete' | 'auth';
  timestamp: number;
  data: Record<string, any>;
}

export interface WebhookDelivery {
  id: string;
  eventId: string;
  endpoint: string;
  status: 'pending' | 'success' | 'failed' | 'retry';
  attempts: number;
  lastAttemptAt?: number;
  nextRetryAt?: number;
  response?: {
    statusCode: number;
    body: string;
  };
}

/**
 * Generate webhook signature using HMAC-SHA256
 */
export async function generateWebhookSignature(
  payload: string,
  secret: string
): Promise<{
  signature: string;
  timestamp: number;
  algorithm: string;
}> {
  const timestamp = Math.floor(Date.now() / 1000);
  const message = `${payload}.${timestamp}`;

  // Generate HMAC-SHA256 signature
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signatureBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  const signature = bufferToHex(signatureBuffer);

  return {
    signature,
    timestamp,
    algorithm: 'HMAC-SHA256',
  };
}

/**
 * Verify webhook signature
 */
export async function verifyWebhookSignature(
  payload: string,
  signature: string,
  timestamp: number,
  secret: string,
  maxAgeSeconds: number = 300
): Promise<{
  valid: boolean;
  reason?: string;
}> {
  // Check timestamp
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > maxAgeSeconds) {
    return { valid: false, reason: 'Timestamp too old or in future' };
  }

  try {
    // Reconstruct message
    const message = `${payload}.${timestamp}`;

    // Compute expected signature
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const expectedBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
    const expectedSignature = bufferToHex(expectedBuffer);

    // Constant-time comparison to prevent timing attacks
    if (!constantTimeEqual(signature, expectedSignature)) {
      return { valid: false, reason: 'Signature mismatch' };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, reason: `Verification error: ${(err as Error).message}` };
  }
}

/**
 * Constant-time string comparison to prevent timing attacks
 */
function constantTimeEqual(a: string, b: string): boolean {
  let result = a.length === b.length ? 0 : 1;

  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Deliver webhook event with retry logic
 */
export async function deliverWebhook(
  event: WebhookEvent,
  endpoint: string,
  secret: string,
  options: {
    maxRetries?: number;
    retryDelayMs?: number;
    timeoutMs?: number;
  } = {}
): Promise<WebhookDelivery> {
  const { maxRetries = 3, retryDelayMs = 1000, timeoutMs = 30000 } = options;

  const delivery: WebhookDelivery = {
    id: `delivery_${crypto.randomUUID()}`,
    eventId: event.id,
    endpoint,
    status: 'pending',
    attempts: 0,
  };

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    delivery.attempts = attempt + 1;
    delivery.lastAttemptAt = Math.floor(Date.now() / 1000);

    try {
      // Generate signature
      const payload = JSON.stringify(event);
      const { signature, timestamp } = await generateWebhookSignature(payload, secret);

      // Send webhook
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Webhook-Event-ID': event.id,
          'X-Webhook-Signature': signature,
          'X-Webhook-Timestamp': timestamp.toString(),
          'X-Webhook-Algorithm': 'HMAC-SHA256',
          'User-Agent': 'DaKingHilsman-Webhooks/1.0',
        },
        body: payload,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      const responseBody = await response.text();

      if (response.ok) {
        delivery.status = 'success';
        delivery.response = {
          statusCode: response.status,
          body: responseBody,
        };
        return delivery;
      }

      // Server error - retry
      if (response.status >= 500) {
        delivery.status = attempt < maxRetries ? 'retry' : 'failed';
        delivery.response = {
          statusCode: response.status,
          body: responseBody,
        };

        if (attempt < maxRetries) {
          delivery.nextRetryAt = Math.floor(Date.now() / 1000) + (retryDelayMs * (attempt + 1)) / 1000;
          await sleep(retryDelayMs * (attempt + 1));
        }
      } else {
        // Client error - don't retry
        delivery.status = 'failed';
        delivery.response = {
          statusCode: response.status,
          body: responseBody,
        };
        return delivery;
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      delivery.status = attempt < maxRetries ? 'retry' : 'failed';

      if (attempt < maxRetries) {
        delivery.nextRetryAt = Math.floor(Date.now() / 1000) + (retryDelayMs * (attempt + 1)) / 1000;
        await sleep(retryDelayMs * (attempt + 1));
      }
    }
  }

  return delivery;
}

/**
 * Parse and validate webhook request
 */
export async function parseWebhookRequest(
  request: Request,
  secret: string
): Promise<{
  valid: boolean;
  event?: WebhookEvent;
  reason?: string;
}> {
  try {
    // Extract headers
    const signature = request.headers.get('X-Webhook-Signature');
    const timestamp = request.headers.get('X-Webhook-Timestamp');
    const eventId = request.headers.get('X-Webhook-Event-ID');

    if (!signature || !timestamp || !eventId) {
      return { valid: false, reason: 'Missing webhook headers' };
    }

    // Parse body
    const body = await request.text();

    // Verify signature
    const ts = parseInt(timestamp, 10);
    if (isNaN(ts)) {
      return { valid: false, reason: 'Invalid timestamp' };
    }

    const verification = await verifyWebhookSignature(body, signature, ts, secret);
    if (!verification.valid) {
      return { valid: false, reason: verification.reason };
    }

    // Parse event
    const event = JSON.parse(body) as WebhookEvent;

    return { valid: true, event };
  } catch (err) {
    return { valid: false, reason: `Parse error: ${(err as Error).message}` };
  }
}

/**
 * Generate webhook endpoint URL with signing key
 */
export function generateWebhookUrl(
  baseUrl: string,
  webhookId: string,
  signingKey: string
): string {
  const params = new URLSearchParams({
    id: webhookId,
    key: signingKey,
  });

  return `${baseUrl}?${params.toString()}`;
}

/**
 * Test webhook delivery
 */
export async function testWebhookDelivery(
  endpoint: string,
  secret: string
): Promise<{
  success: boolean;
  statusCode?: number;
  error?: string;
  latency?: number;
}> {
  const testEvent: WebhookEvent = {
    id: 'test_' + crypto.randomUUID(),
    type: 'auth',
    timestamp: Math.floor(Date.now() / 1000),
    data: {
      message: 'Webhook delivery test',
      testMode: true,
    },
  };

  const startTime = performance.now();

  try {
    const delivery = await deliverWebhook(testEvent, endpoint, secret, {
      maxRetries: 1,
      timeoutMs: 10000,
    });

    const latency = Math.round(performance.now() - startTime);

    if (delivery.status === 'success') {
      return {
        success: true,
        statusCode: delivery.response?.statusCode,
        latency,
      };
    } else {
      return {
        success: false,
        statusCode: delivery.response?.statusCode,
        error: `Delivery failed: ${delivery.status}`,
        latency,
      };
    }
  } catch (err) {
    const latency = Math.round(performance.now() - startTime);
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
      latency,
    };
  }
}

/**
 * Create webhook event from media action
 */
export function createMediaEvent(
  type: 'upload' | 'download' | 'delete',
  data: {
    fileId: string;
    filename: string;
    size: number;
    userId: string;
    url?: string;
  }
): WebhookEvent {
  return {
    id: `event_${crypto.randomUUID()}`,
    type,
    timestamp: Math.floor(Date.now() / 1000),
    data,
  };
}

/**
 * Helper: Convert buffer to hex string
 */
function bufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Helper: Sleep for specified milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
