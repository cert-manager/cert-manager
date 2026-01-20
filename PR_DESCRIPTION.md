# Add AWS, GCP, and Azure Authentication Methods for Vault Issuer

## What this PR does

This adds support for authenticating to HashiCorp Vault using cloud provider identity systems instead of static credentials. You can now use AWS IAM roles, GCP Workload Identity, or Azure Managed Identity to authenticate cert-manager with your Vault server.

## Why we need this

Right now, if you want cert-manager to talk to Vault, you need to manage static tokens or AppRole credentials. This works, but it means:

- You have to rotate secrets manually (or build automation for it)
- Credentials can leak if someone gets access to your Kubernetes secrets
- It's extra operational work that cloud-native environments shouldn't need

Cloud providers already solved this problem with workload identity. Your pods can automatically get short-lived tokens tied to their identity - no secrets to manage, no rotation headaches, better security overall.

## What changed

**New API types** in `pkg/apis/certmanager/v1/types_issuer.go`:
- `VaultAWSAuth` - for AWS IAM authentication (supports IRSA and EC2 instance profiles)
- `VaultGCPAuth` - for GCP authentication (supports Workload Identity and GCE service accounts)  
- `VaultAzureAuth` - for Azure authentication (supports MSI and Workload Identity)

**New auth functions** in `internal/vault/vault.go`:
- `requestTokenWithAWSAuth()` - handles the AWS auth flow with Vault
- `requestTokenWithGCPAuth()` - handles the GCP auth flow with Vault
- `requestTokenWithAzureAuth()` - handles the Azure auth flow with Vault

**Updated validation** in `internal/apis/certmanager/validation/issuer.go`:
- Added validation rules for the new auth methods

**Updated setup logic** in `pkg/issuer/vault/setup.go`:
- Extended to recognize and validate the new auth types

## How to use it

Here's what an AWS-authenticated issuer looks like:

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: vault-issuer
spec:
  vault:
    server: https://vault.example.com
    path: pki/sign/example-dot-com
    auth:
      aws:
        role: cert-manager-role
        region: us-east-1
        serviceAccountRef:
          name: cert-manager
```

GCP and Azure follow the same pattern - just swap `aws` for `gcp` or `azure` and adjust the fields accordingly.

## Related issue

Closes #8352
