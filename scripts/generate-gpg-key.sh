#!/bin/bash
set -e

# Script to generate GPG key for repository signing
# This key will be used to sign Debian and RPM repositories

echo "Generating GPG key for repository signing..."

# Create GPG batch file for unattended key generation
cat > /tmp/gpg-batch.txt << EOF
%echo Generating GPG key for Foundation Storage Engine repositories
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: Foundation Storage Engine
Name-Email: alessio@linux.com
Expire-Date: 2y
%no-protection
%commit
%echo done
EOF

# Generate the key
gpg --batch --generate-key /tmp/gpg-batch.txt

# Clean up
rm -f /tmp/gpg-batch.txt

# Get the key ID
KEY_ID=$(gpg --list-secret-keys --keyid-format LONG alessio@linux.com | grep sec | awk '{print $2}' | cut -d'/' -f2)

echo "GPG Key generated successfully!"
echo "Key ID: $KEY_ID"
echo ""
echo "To export the private key (for GitHub secrets):"
echo "  gpg --armor --export-secret-keys $KEY_ID > foundation-repo-signing.key"
echo ""
echo "To export the public key (for users to import):"
echo "  gpg --armor --export $KEY_ID > foundation-repo-signing.pub"
echo ""
echo "To add to GitHub secrets:"
echo "  1. Copy the content of foundation-repo-signing.key"
echo "  2. Add it as a secret named 'GPG_PRIVATE_KEY' in your repository"
echo "  3. Add the key ID as a secret named 'GPG_KEY_ID'"
echo ""
echo "Users will import the public key with:"
echo "  curl -fsSL https://apt.mirror.s3.amazonaws.com/foundation-repo-signing.pub | sudo apt-key add -"