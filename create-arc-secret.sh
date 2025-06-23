#!/bin/bash

# DO NOT commit this file to git!
# Add to .gitignore

echo "Enter your GitHub PAT (it will be hidden):"
read -s GITHUB_PAT

kubectl create secret generic controller-manager \
  --namespace=arc-system \
  --from-literal=github_token="${GITHUB_PAT}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Secret created successfully"