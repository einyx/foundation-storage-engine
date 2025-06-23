#!/bin/bash

cat > index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Foundation Storage Engine - Debian Repository</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 { color: #2c3e50; }
        pre {
            background: #f4f4f4;
            border: 1px solid #ddd;
            padding: 10px;
            overflow-x: auto;
        }
        code {
            background: #f4f4f4;
            padding: 2px 5px;
            border-radius: 3px;
        }
        .warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <h1>Foundation Storage Engine - Debian Repository</h1>
    
    <p>This is the official Debian package repository for Foundation Storage Engine.</p>
    
    <h2>Installation</h2>
    
    <h3>Add the repository to your system:</h3>
    
    <pre><code># Add the repository
echo "deb https://foundation-storage-engine-debian-mirror.s3.amazonaws.com/ stable main" | sudo tee /etc/apt/sources.list.d/foundation-storage-engine.list

# Update package list
sudo apt update

# Install the package
sudo apt install foundation-storage-engine</code></pre>
    
    <div class="warning">
        <strong>Note:</strong> This repository is unsigned. You may need to use <code>--allow-unauthenticated</code> flag or configure apt to allow unsigned repositories.
    </div>
    
    <h3>Alternative: Direct download</h3>
    
    <p>You can also browse and download packages directly:</p>
    <ul>
        <li><a href="pool/main/f/foundation-storage-engine/">Browse all packages</a></li>
    </ul>
    
    <h2>Supported Architectures</h2>
    <ul>
        <li>amd64 (x86_64)</li>
        <li>arm64 (aarch64)</li>
    </ul>
    
    <h2>More Information</h2>
    <ul>
        <li><a href="https://github.com/meshxdata/foundation-storage-engine">GitHub Repository</a></li>
        <li><a href="https://github.com/meshxdata/foundation-storage-engine/releases">All Releases</a></li>
    </ul>
</body>
</html>
EOF

# Create a simple directory listing for pool
mkdir -p debian/pool/main/f/foundation-storage-engine
cat > debian/pool/main/f/foundation-storage-engine/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Package Directory</title>
    <style>
        body { font-family: monospace; margin: 20px; }
        a { text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h2>Foundation Storage Engine Packages</h2>
    <a href="../../../../../">[Parent Directory]</a><br><br>
EOF