# sts-irsa-proxy

A Kubernetes DaemonSet that proxies sts.amazonaws.com API requests to intercept
and replace Service Account tokens with OIDC tokens from a global OIDC
provider, rather than one that is cluster-specific.

This allows IAM role trust policies to specify a single OIDC provider. Then, we
could provision a new cluster or replace a cluster without having to update all
IAM role trust policies. This also helps avoid trust policy limits which only
support up to ~11 federated OIDC providers within trust policy length limit of
4096 characters.
