import type { Finding } from './types.js';

export const FAKE_FINDINGS: Finding[] = [
  // Semgrep findings
  {
    tool: 'semgrep',
    rule: 'python.django.security.injection.sql',
    severity: 'high',
    location: 'controllers/search.py',
    line: 42,
    message: 'User input concatenated directly into raw SQL query'
  },
  {
    tool: 'semgrep',
    rule: 'javascript.express.security.command-injection',
    severity: 'high',
    location: 'services/execService.js',
    line: 78,
    message: 'Unsanitized user payload passed to child_process.exec'
  },
  {
    tool: 'semgrep',
    rule: 'javascript.react.security.audit.xss',
    severity: 'high',
    location: 'client/components/UserProfile.tsx',
    line: 114,
    message: 'Use of dangerouslySetInnerHTML with untrusted user profile data'
  },
  {
    tool: 'semgrep',
    rule: 'python.lang.security.deserialization.pickle',
    severity: 'high',
    location: 'workers/cache_worker.py',
    line: 33,
    message: 'Insecure deserialization using pickle.loads on incoming stream'
  },
  {
    tool: 'semgrep',
    rule: 'javascript.node.security.path-traversal',
    severity: 'high',
    location: 'routes/downloads.js',
    line: 56,
    message: 'Path traversal vulnerability: user parameter used in fs.readFile without sanitization'
  },
  {
    tool: 'semgrep',
    rule: 'python.requests.security.ssrf',
    severity: 'high',
    location: 'integrations/webhook.py',
    line: 89,
    message: 'Unvalidated URL passed directly to requests.post causing SSRF'
  },
  {
    tool: 'semgrep',
    rule: 'javascript.crypto.weak-hash.md5',
    severity: 'medium',
    location: 'utils/auth.js',
    line: 19,
    message: 'Weak hashing algorithm MD5 used for password fingerprinting'
  },
  {
    tool: 'semgrep',
    rule: 'javascript.express.security.cors-wildcard',
    severity: 'medium',
    location: 'server.js',
    line: 25,
    message: 'Access-Control-Allow-Origin header set to unrestricted wildcard (*)'
  },
  {
    tool: 'semgrep',
    rule: 'python.flask.security.cookie-without-httponly',
    severity: 'medium',
    location: 'controllers/auth.py',
    line: 67,
    message: 'Session cookie created without HttpOnly and Secure flags'
  },
  {
    tool: 'semgrep',
    rule: 'javascript.jwt.hardcoded-jwt-secret',
    severity: 'high',
    location: 'middleware/verifyToken.js',
    line: 15,
    message: 'JWT verification with default fallback secret key string'
  },
  {
    tool: 'semgrep',
    rule: 'javascript.express.security.open-redirect',
    severity: 'medium',
    location: 'routes/login.js',
    line: 104,
    message: 'Untrusted target URL parameter used in res.redirect'
  },
  {
    tool: 'semgrep',
    rule: 'python.cryptography.insecure-cipher-mode',
    severity: 'medium',
    location: 'services/encryption.py',
    line: 45,
    message: 'ECB mode used with AES cipher instead of authenticated GCM/CBC'
  },
  {
    tool: 'semgrep',
    rule: 'javascript.node.security.regex-dos',
    severity: 'low',
    location: 'utils/validator.js',
    line: 82,
    message: 'Regular expression susceptible to catastrophic backtracking (ReDoS)'
  },
  {
    tool: 'semgrep',
    rule: 'javascript.express.security.missing-helmet',
    severity: 'low',
    location: 'app.js',
    line: 12,
    message: 'Security headers missing; helmet middleware recommended'
  },

  // Trivy findings (dependencies and configuration)
  {
    tool: 'trivy',
    rule: 'CVE-2023-45133',
    severity: 'high',
    location: 'package.json:axios@0.21.1',
    line: 28,
    message: 'Axios SSRF vulnerability via follow-redirects chain'
  },
  {
    tool: 'trivy',
    rule: 'CVE-2022-29078',
    severity: 'high',
    location: 'package.json:ejs@3.1.6',
    line: 34,
    message: 'Remote Code Execution in ejs through settings.view[options]'
  },
  {
    tool: 'trivy',
    rule: 'CVE-2023-38606',
    severity: 'high',
    location: 'package.json:express-fileupload@1.4.0',
    line: 41,
    message: 'Prototype pollution leads to arbitrary file overwrite'
  },
  {
    tool: 'trivy',
    rule: 'CVE-2022-25883',
    severity: 'medium',
    location: 'package.json:semver@7.3.5',
    line: 52,
    message: 'Regular Expression Denial of Service in semver range parsing'
  },
  {
    tool: 'trivy',
    rule: 'CVE-2023-26159',
    severity: 'medium',
    location: 'package.json:follow-redirects@1.15.2',
    line: 63,
    message: 'Potential memory leak and unhandled redirect loop'
  },
  {
    tool: 'trivy',
    rule: 'CVE-2023-28154',
    severity: 'medium',
    location: 'package.json:webpack@5.76.0',
    line: 18,
    message: 'Improper restriction of operations within the bounds of a memory buffer'
  },
  {
    tool: 'trivy',
    rule: 'CVE-2024-21490',
    severity: 'medium',
    location: 'package.json:angular@1.8.2',
    line: 77,
    message: 'Cross-site scripting (XSS) via SVG element processing'
  },
  {
    tool: 'trivy',
    rule: 'CVE-2021-3749',
    severity: 'low',
    location: 'package.json:axios@0.21.1',
    line: 28,
    message: 'Regular expression denial of service in trim method'
  },
  {
    tool: 'trivy',
    rule: 'CVE-2022-0235',
    severity: 'low',
    location: 'package.json:node-fetch@2.6.6',
    line: 88,
    message: 'Exposure of sensitive information to an unauthorized actor'
  },
  {
    tool: 'trivy',
    rule: 'TRIVY-CONFIG-001',
    severity: 'low',
    location: 'Dockerfile:3',
    line: 3,
    message: 'Base image specifies latest tag rather than pinned digest'
  },

  // Gitleaks findings (secrets & credentials)
  {
    tool: 'gitleaks',
    rule: 'aws-access-token',
    severity: 'high',
    location: 'config/aws.env',
    line: 7,
    message: 'AWS Access Key ID exposed: AKIAIOSFODNN7EXAMPLE'
  },
  {
    tool: 'gitleaks',
    rule: 'github-pat',
    severity: 'high',
    location: '.env.production',
    line: 14,
    message: 'GitHub Personal Access Token exposed: ghp_abc1234567890def'
  },
  {
    tool: 'gitleaks',
    rule: 'private-key',
    severity: 'high',
    location: 'certs/server.key',
    line: 1,
    message: 'Unencrypted RSA private key block found in repository'
  },
  {
    tool: 'gitleaks',
    rule: 'slack-webhook-url',
    severity: 'high',
    location: 'scripts/notify.sh',
    line: 22,
    message: 'Slack incoming webhook URL exposed with administrative access'
  },
  {
    tool: 'gitleaks',
    rule: 'stripe-secret-key',
    severity: 'high',
    location: 'test/fixtures/secrets.json',
    line: 5,
    message: 'Stripe live secret API key pattern identified: sk_live_mock...'
  },
  {
    tool: 'gitleaks',
    rule: 'generic-api-key',
    severity: 'high',
    location: 'services/mailer.ts',
    line: 12,
    message: 'Sendgrid API Key pattern exposed: SG.randomMockString'
  }
];
