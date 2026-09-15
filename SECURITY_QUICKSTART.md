# Security Quick Start Guide

Get your media platform fully secured with SSL/TLS, mutual TLS, client certificates, webhooks, and Azure integration in 30 minutes.

## 5-Minute Setup

### 1. Deploy Base Platform

```bash
npm install
npm run build
npm run deploy
```

Your platform is now live with:
- ✅ Automatic HTTPS (Cloudflare)
- ✅ Token-based auth
- ✅ R2 storage

### 2. Verify HTTPS Works

```bash
curl -I https://dakinghilsman.tv
# Should show: HTTP/2 200
```

## 15-Minute: Enable mTLS + Webhook Validation

### Step 1: Add Environment Variables

Edit `wrangler.jsonc`:

```jsonc
{
  "env": {
    "production": {
      "vars": {
        "ENABLE_MTLS": "true",
        "ENABLE_WEBHOOK_VALIDATION": "true"
      }
    }
  }
}
```

### Step 2: Deploy Updated Config

```bash
npm run deploy
```

### Step 3: Configure Admin Key

Set strong admin key in your secrets:

```bash
# Option 1: Environment variable
export ADMIN_KEY="your-very-strong-random-key-here"

# Option 2: Add to .env.local (local development only)
echo "ADMIN_KEY=your-key" >> .env.local
```

### Step 4: Add Your Certificates

Upload your trusted certificate bundle:

```bash
# Convert binary certificate to JSON format
cat trusted_certs.crt | sed 's/^/  "/' | sed 's/$/\\n"/' > certs.json

# Add to platform
curl -X POST https://dakinghilsman.tv/api/certs/add \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer production-admin-key" \
  -d '{
    "certificate": "'"$(cat trusted_certs.crt | tr '\n' ' ')"'",
    "name": "Trusted Certificate Authority"
  }'
```

### Step 5: Configure Webhooks

```bash
curl -X POST https://dakinghilsman.tv/api/webhooks/config \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer production-admin-key" \
  -d '{
    "endpoint": "https://your-app.com/webhooks/media",
    "secret": "your-webhook-secret-key",
    "events": ["upload", "download", "delete"]
  }'
```

### Step 6: Verify Security Is Enabled

```bash
curl https://dakinghilsman.tv/api/health | jq '.security'
# Should show:
# {
#   "mtlsEnabled": true,
#   "webhookValidationEnabled": true,
#   "trustedCertificates": 1
# }
```

## 30-Minute: Azure Integration (Optional)

### Step 1: Setup Azure Account

```bash
# Login to Azure
az login

# Create resource group
az group create --name media-rg --location eastus

# Create Key Vault
az keyvault create \
  --name my-keyvault \
  --resource-group media-rg \
  --location eastus
```

### Step 2: Add Azure Certificates

```bash
# Upload your Azure certificates
curl -X POST https://dakinghilsman.tv/api/certs/add \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer production-admin-key" \
  -d '{
    "certificate": "'"$(cat azure-cert.crt | tr '\n' ' ')"'",
    "name": "Azure Service Principal"
  }'
```

### Step 3: Set Azure Credentials

```bash
# Update wrangler.jsonc
{
  "env": {
    "production": {
      "vars": {
        "AZURE_TENANT_ID": "your-tenant-id",
        "AZURE_CLIENT_ID": "your-client-id",
        "AZURE_STORAGE_ACCOUNT": "your-storage-account",
        "AZURE_BLOB_CONTAINER": "media"
      }
    }
  }
}
```

### Step 4: Deploy with Azure Support

```bash
npm run deploy
```

## Testing Your Security Setup

### Test 1: Basic Authentication

```bash
# Should fail without token
curl -X GET https://dakinghilsman.tv/api/files
# Returns: 401 Unauthorized

# Should work with token
TOKEN=$(curl -X POST https://dakinghilsman.tv/api/auth \
  -H "Content-Type: application/json" \
  -d '{"userId":"test@example.com"}' | jq -r '.token')

curl -X GET https://dakinghilsman.tv/api/files \
  -H "Authorization: Bearer $TOKEN"
# Returns: 200 OK with file list
```

### Test 2: mTLS Certificate Validation

```bash
# Generate test certificate
openssl genrsa -out test.key 2048
openssl req -new -x509 -key test.key -out test.crt -days 365 -subj "/CN=test"

# Upload to platform
curl -X POST https://dakinghilsman.tv/api/certs/add \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer production-admin-key" \
  -d '{
    "certificate": "'"$(cat test.crt | tr '\n' ' ')"'",
    "name": "Test Certificate"
  }'

# Test request with certificate
curl -X POST https://dakinghilsman.tv/api/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Client-Cert: $(cat test.crt)" \
  -H "X-Cert-Timestamp: $(date +%s)" \
  -F "file=@test.txt"
# Should work with certificate
```

### Test 3: Webhook Validation

```bash
# Create test webhook receiver (local Python)
python3 << 'EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import hmac
import hashlib

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        signature = self.headers.get('X-Webhook-Signature')
        timestamp = self.headers.get('X-Webhook-Timestamp')
        
        print(f"Received webhook:")
        print(f"  Signature: {signature}")
        print(f"  Timestamp: {timestamp}")
        print(f"  Body: {body.decode()}")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True}).encode())

server = HTTPServer(('localhost', 8000), WebhookHandler)
print("Webhook receiver listening on http://localhost:8000")
server.serve_forever()
EOF

# In another terminal, trigger an upload to fire webhook
```

### Test 4: Certificate Chain Validation

```bash
# Verify certificate chain
curl https://dakinghilsman.tv/api/certs/list \
  -H "Authorization: Bearer production-admin-key" | jq '.certificates'

# Should show all uploaded certificates
```

## Security Checklist

### Before Production

- [ ] HTTPS enabled on all three domains
- [ ] Cloudflare SSL mode set to "Full (strict)"
- [ ] mTLS enabled and tested
- [ ] Trusted certificates uploaded
- [ ] Webhook validation configured and tested
- [ ] Admin authentication key is strong (32+ characters)
- [ ] Certificate expiration monitoring set up
- [ ] Rate limiting enabled on endpoints
- [ ] CORS headers reviewed
- [ ] Audit logging enabled

### Ongoing Maintenance

- [ ] Weekly: Check certificate expiration status
- [ ] Monthly: Review webhook delivery logs
- [ ] Quarterly: Rotate admin authentication keys
- [ ] Quarterly: Audit certificate permissions
- [ ] Annually: Full security audit

## Troubleshooting

### "Certificate not found" Error

```bash
# Check what certificates are stored
curl https://dakinghilsman.tv/api/certs/list \
  -H "Authorization: Bearer production-admin-key"

# Add certificate if missing
curl -X POST https://dakinghilsman.tv/api/certs/add \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer production-admin-key" \
  -d '{...}'
```

### "mTLS handshake failed" Error

```bash
# Verify certificate is valid
openssl x509 -in cert.crt -text -noout

# Check certificate is in trusted list
curl https://dakinghilsman.tv/api/certs/list \
  -H "Authorization: Bearer production-admin-key" | \
  grep "certificate-name"

# Ensure timestamp header is included
curl -X POST https://dakinghilsman.tv/api/upload \
  -H "X-Cert-Timestamp: $(date +%s)"
```

### "Webhook validation failed" Error

```bash
# Verify webhook signature matches
# Get webhook secret from Key Vault (if using Azure)
az keyvault secret show \
  --vault-name my-keyvault \
  --name webhook-secret

# Reconfigure webhook with correct secret
curl -X POST https://dakinghilsman.tv/api/webhooks/config \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer production-admin-key" \
  -d '{
    "endpoint": "https://your-endpoint.com",
    "secret": "correct-secret-key"
  }'
```

## Next Steps

1. **Read Detailed Guides:**
   - [SSL_TLS_SETUP.md](./SSL_TLS_SETUP.md) - Complete SSL/TLS documentation
   - [AZURE_INTEGRATION.md](./AZURE_INTEGRATION.md) - Azure services integration

2. **Production Checklist:**
   - [DEPLOYMENT.md](./DEPLOYMENT.md) - Full deployment guide

3. **Monitor & Alert:**
   - Set up Cloudflare alerts for SSL/TLS issues
   - Create Slack/email notifications for certificate expiration
   - Enable audit logging in Cloudflare dashboard

4. **Team Training:**
   - Share certificate handling procedures with team
   - Document API client certificate setup
   - Create runbook for certificate rotation

## Support

- **Cloudflare Support:** https://support.cloudflare.com
- **Azure Support:** https://support.microsoft.com/en-us/support
- **SSL Labs:** https://www.ssllabs.com/ssltest/
- **OWASP:** https://owasp.org/
