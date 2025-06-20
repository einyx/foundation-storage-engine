#!/bin/bash
set -e

# Setup IAM Role for S3Proxy on EKS
# This script creates an IAM role that can be assumed by the s3proxy service account

# Configuration
CLUSTER_NAME=${1:-"my-eks-cluster"}
NAMESPACE=${2:-"dev"}
SERVICE_ACCOUNT=${3:-"s3proxy"}
ROLE_NAME=${4:-"s3proxy-eks-role"}
AWS_REGION=${AWS_REGION:-"us-east-1"}
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "🔧 Setting up IAM Role for S3Proxy on EKS"
echo "   Cluster: $CLUSTER_NAME"
echo "   Namespace: $NAMESPACE"
echo "   Service Account: $SERVICE_ACCOUNT"
echo "   IAM Role: $ROLE_NAME"
echo "   AWS Account: $AWS_ACCOUNT_ID"
echo ""

# Get OIDC provider URL
OIDC_PROVIDER=$(aws eks describe-cluster \
  --name "$CLUSTER_NAME" \
  --region "$AWS_REGION" \
  --query "cluster.identity.oidc.issuer" \
  --output text | sed -e "s/^https:\/\///")

if [ -z "$OIDC_PROVIDER" ]; then
  echo "❌ Could not get OIDC provider for cluster $CLUSTER_NAME"
  exit 1
fi

echo "✅ OIDC Provider: $OIDC_PROVIDER"

# Create trust policy
cat > /tmp/trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${NAMESPACE}:${SERVICE_ACCOUNT}",
          "${OIDC_PROVIDER}:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
EOF

# Create S3 access policy
cat > /tmp/s3-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ProxyFullAccess",
      "Effect": "Allow",
      "Action": [
        "s3:*"
      ],
      "Resource": [
        "arn:aws:s3:::*"
      ]
    }
  ]
}
EOF

# Create IAM role
echo "📝 Creating IAM role..."
aws iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document file:///tmp/trust-policy.json \
  --description "IAM role for s3proxy service on EKS" \
  2>/dev/null || echo "   Role already exists, updating trust policy..."

# Update trust policy if role exists
aws iam update-assume-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-document file:///tmp/trust-policy.json

# Attach S3 policy
echo "📎 Attaching S3 access policy..."
aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name S3ProxyAccess \
  --policy-document file:///tmp/s3-policy.json

# Create namespace if it doesn't exist
echo "🏷️  Creating namespace..."
kubectl create namespace "$NAMESPACE" 2>/dev/null || echo "   Namespace already exists"

# Create service account with annotation
echo "👤 Creating service account with IAM role annotation..."
kubectl create serviceaccount "$SERVICE_ACCOUNT" -n "$NAMESPACE" 2>/dev/null || echo "   Service account already exists"

# Annotate service account
kubectl annotate serviceaccount "$SERVICE_ACCOUNT" \
  -n "$NAMESPACE" \
  eks.amazonaws.com/role-arn=arn:aws:iam::"${AWS_ACCOUNT_ID}":role/"${ROLE_NAME}" \
  --overwrite

# Clean up temp files
rm -f /tmp/trust-policy.json /tmp/s3-policy.json

echo ""
echo "✅ IAM Role setup complete!"
echo ""
echo "📋 Next steps:"
echo "   1. Update helm-values-aws-dev.yaml with your account ID:"
echo "      sed -i 's/YOUR_ACCOUNT_ID/${AWS_ACCOUNT_ID}/g' helm-values-aws-dev.yaml"
echo ""
echo "   2. Install S3Proxy with Helm:"
echo "      helm install s3proxy-minio ./charts/s3proxy -n $NAMESPACE -f helm-values-aws-dev.yaml"
echo ""
echo "   3. Verify the deployment:"
echo "      kubectl get pods -n $NAMESPACE"
echo "      kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=s3proxy"
echo ""
echo "🔐 The service will use IAM role: arn:aws:iam::${AWS_ACCOUNT_ID}:role/${ROLE_NAME}"
