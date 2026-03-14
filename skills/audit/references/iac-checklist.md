# Infrastructure as Code Security Checklist

## Dockerfile

### CRITICAL
- [ ] NOT running as root — `USER nonroot` or `USER 1001` before final CMD/ENTRYPOINT
- [ ] No secrets in ENV, ARG, or COPY at build time (visible in `docker history`)
- [ ] No `.env`, `*.pem`, `*.key`, `id_rsa`, `credentials` in COPY context
  - Check: `COPY . .` without a thorough `.dockerignore`

### HIGH
- [ ] Base image pinned to digest or exact version — NOT `latest`
  ```dockerfile
  # BAD
  FROM node:latest
  FROM python:3
  # GOOD
  FROM node:20.11.0-alpine3.19
  FROM python:3.12.2-slim
  ```
- [ ] Multi-stage build to exclude dev dependencies and build tools from final image
- [ ] `apt-get install --no-install-recommends` and clean cache in same RUN layer
  ```dockerfile
  RUN apt-get update && apt-get install -y --no-install-recommends \
      curl=7.88.1 \
  && rm -rf /var/lib/apt/lists/*
  ```
- [ ] `HEALTHCHECK` defined
- [ ] Minimal base image (alpine, slim, distroless)

### MEDIUM
- [ ] `RUN` commands don't use `curl | bash` pattern (blind execution)
- [ ] External package checksums verified where possible
- [ ] `EXPOSE` declares only actually needed ports


## Kubernetes / Helm

### CRITICAL
- [ ] `securityContext.runAsNonRoot: true` on all containers
- [ ] `securityContext.privileged: false` (default false, but explicit is better)
- [ ] No `hostNetwork: true`, `hostPID: true`, `hostIPC: true`
- [ ] Secrets not stored in ConfigMaps (use Secret objects or external secret manager)

### HIGH
- [ ] Resource limits defined (CPU and memory) — missing limits = DoS risk
  ```yaml
  resources:
    limits:
      cpu: "500m"
      memory: "512Mi"
    requests:
      cpu: "100m"
      memory: "128Mi"
  ```
- [ ] `readOnlyRootFilesystem: true` where possible
- [ ] `allowPrivilegeEscalation: false`
- [ ] `capabilities.drop: ["ALL"]` — then add back only needed capabilities
- [ ] NetworkPolicy defined to restrict pod-to-pod communication
- [ ] Service accounts with minimal RBAC (principle of least privilege)
- [ ] RBAC: no ClusterAdmin granted to application workloads

### MEDIUM
- [ ] Image pull policy: `Always` for `:latest`, `IfNotPresent` for pinned versions
- [ ] Liveness and readiness probes defined
- [ ] Secrets injected via volumes or external secrets operator, not env vars (env vars visible in `kubectl describe`)
- [ ] Ingress with TLS termination
- [ ] Pod disruption budget for critical workloads


## Terraform / AWS IaC

### CRITICAL
- [ ] No hardcoded credentials in `.tf` files — use `data "aws_secretsmanager_secret"` or env vars
- [ ] S3: `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets` all `true`
- [ ] Security groups: no `0.0.0.0/0` on non-web ports (22, 3306, 5432, 6379, etc.)
  ```hcl
  # BAD — SSH open to the internet
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  ```
- [ ] IAM: no `"Action": "*"` or `"Resource": "*"` in custom policies
- [ ] RDS: `publicly_accessible = false`

### HIGH
- [ ] S3 buckets with sensitive data have encryption: `server_side_encryption_configuration`
- [ ] RDS encryption at rest: `storage_encrypted = true`
- [ ] EBS volumes encrypted: `encrypted = true`
- [ ] CloudTrail enabled in all regions: `is_multi_region_trail = true`
- [ ] VPC flow logs enabled
- [ ] ALB/ELB: HTTPS listener with modern TLS policy (`ELBSecurityPolicy-TLS13-1-2-2021-06`)
- [ ] Lambda: no overpermissive execution role
- [ ] KMS key rotation enabled: `enable_key_rotation = true`

### MEDIUM
- [ ] Terraform state in remote backend (S3 + DynamoDB locking), not local
- [ ] State bucket versioning and encryption enabled
- [ ] MFA delete on S3 buckets with state / sensitive data
- [ ] GuardDuty enabled
- [ ] Config rules enabled for compliance monitoring
- [ ] Secrets Manager or Parameter Store (SecureString) instead of plaintext SSM params


## GitHub Actions / CI-CD

### CRITICAL
- [ ] `pull_request_target` trigger does NOT checkout untrusted code from the PR
  ```yaml
  # DANGEROUS — executes PR author's workflow with write permissions
  on: pull_request_target
  jobs:
    build:
      steps:
        - uses: actions/checkout@v4
          with:
            ref: ${{ github.event.pull_request.head.sha }}  # Attacker-controlled
  ```
- [ ] Secrets never printed to logs — no `echo $SECRET`, `env` dump, `set -x` with secrets
- [ ] GITHUB_TOKEN permissions scoped minimally
  ```yaml
  permissions:
    contents: read   # Not: permissions: write-all
  ```

### HIGH
- [ ] Action versions pinned to full SHA, not branch or tag (supply chain attack vector)
  ```yaml
  # BAD — tag can be moved
  uses: actions/checkout@v4
  # GOOD — SHA is immutable
  uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
  ```
- [ ] Environment protection rules on production deployments (required reviewers)
- [ ] `CODEOWNERS` file to require review of security-sensitive paths
- [ ] No `run: curl ${{ github.event.inputs.url }}` — user inputs can inject shell commands
  ```yaml
  # Script injection — input contains: `; malicious_command #`
  - run: echo "Input: ${{ github.event.inputs.name }}"
  # Fix: use environment variable, not inline interpolation
  - env:
      NAME: ${{ github.event.inputs.name }}
    run: echo "Input: $NAME"
  ```

### MEDIUM
- [ ] Dependabot or Renovate enabled for action version updates
- [ ] Branch protection: require PR reviews, status checks, no force push to main
- [ ] `pull_request` (not `pull_request_target`) for untrusted contributor workflows
- [ ] Artifact retention minimized (don't store sensitive build artifacts indefinitely)
- [ ] OpenID Connect (OIDC) instead of long-lived cloud credentials in secrets


## nginx / Web Server Config

### HIGH
- [ ] TLS 1.2+ only — disable TLS 1.0, TLS 1.1, SSLv3
  ```nginx
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...';
  ```
- [ ] HSTS header: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`
- [ ] Directory listing disabled: `autoindex off;`
- [ ] Server version not exposed: `server_tokens off;`

### MEDIUM
- [ ] Security headers:
  ```nginx
  add_header X-Frame-Options "SAMEORIGIN";
  add_header X-Content-Type-Options "nosniff";
  add_header Referrer-Policy "strict-origin-when-cross-origin";
  add_header Permissions-Policy "geolocation=(), microphone=()";
  add_header Content-Security-Policy "default-src 'self'; ...";
  ```
- [ ] Rate limiting on auth endpoints:
  ```nginx
  limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
  location /login { limit_req zone=login burst=3; ... }
  ```
- [ ] `client_max_body_size` set appropriately (default 1MB, may need adjustment)
- [ ] Access log with real client IP (behind load balancer: `real_ip_header X-Forwarded-For`)
