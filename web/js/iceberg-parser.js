// Data lake file format parser (Iceberg, Parquet, Hive, Trino)
class IcebergMetadataParser {
    constructor() {
        this.metadataCache = new Map();
    }

    // Check if a file is an Iceberg metadata file
    isIcebergMetadata(key) {
        return key.includes('metadata') && key.endsWith('.json');
    }

    // Check if a file is an Iceberg manifest file
    isIcebergManifest(key) {
        return key.includes('manifest') && (key.endsWith('.avro') || key.endsWith('.json'));
    }

    // Check if a file is a Parquet file
    isParquetFile(key) {
        return key.endsWith('.parquet') || key.endsWith('.parq');
    }

    // Check if a file is an ORC file (common in Hive/Trino)
    isORCFile(key) {
        return key.endsWith('.orc');
    }

    // Check if a file is an Avro file
    isAvroFile(key) {
        return key.endsWith('.avro');
    }

    // Check if path contains Hive partitions (e.g., year=2023/month=01/day=15)
    isHivePartitionedPath(path) {
        return /\w+=\w+/.test(path);
    }

    // Get color hex value for file types
    getFileTypeColorHex(color, shade = '500') {
        const colors = {
            blue: {
                '100': '#dbeafe',
                '400': '#60a5fa',
                '500': '#3b82f6',
                '600': '#2563eb',
                '800': '#1e40af'
            },
            green: {
                '100': '#dcfce7',
                '400': '#4ade80',
                '500': '#22c55e',
                '600': '#16a34a',
                '800': '#166534'
            },
            purple: {
                '100': '#f3e8ff',
                '400': '#c084fc',
                '500': '#a855f7',
                '600': '#9333ea',
                '800': '#6b21a8'
            },
            yellow: {
                '100': '#fef3c7',
                '400': '#facc15',
                '500': '#eab308',
                '600': '#ca8a04',
                '800': '#854d0e'
            },
            gray: {
                '100': '#f3f4f6',
                '400': '#9ca3af',
                '500': '#6b7280',
                '600': '#4b5563',
                '800': '#1f2937'
            },
            red: {
                '100': '#fee2e2',
                '400': '#f87171',
                '500': '#ef4444',
                '600': '#dc2626',
                '800': '#991b1b'
            },
            orange: {
                '100': '#fed7aa',
                '400': '#fb923c',
                '500': '#f97316',
                '600': '#ea580c',
                '800': '#9a3412'
            }
        };
        
        return colors[color] && colors[color][shade] || '#6b7280'; // Default to gray
    },

    // Get file type and metadata
    getFileTypeInfo(key) {
        const lowerKey = key.toLowerCase();
        
        if (this.isParquetFile(lowerKey)) {
            return {
                type: 'parquet',
                name: 'Apache Parquet',
                icon: 'database',
                color: 'blue',
                description: 'Columnar storage format'
            };
        }
        
        if (this.isORCFile(lowerKey)) {
            return {
                type: 'orc',
                name: 'Apache ORC',
                icon: 'database',
                color: 'green',
                description: 'Optimized Row Columnar format'
            };
        }
        
        if (this.isAvroFile(lowerKey)) {
            return {
                type: 'avro',
                name: 'Apache Avro',
                icon: 'database',
                color: 'purple',
                description: 'Row-oriented data serialization'
            };
        }
        
        if (lowerKey.endsWith('.json')) {
            return {
                type: 'json',
                name: 'JSON',
                icon: 'code',
                color: 'yellow',
                description: 'JavaScript Object Notation'
            };
        }
        
        if (lowerKey.endsWith('.csv')) {
            return {
                type: 'csv',
                name: 'CSV',
                icon: 'table',
                color: 'gray',
                description: 'Comma-separated values'
            };
        }
        
        return null;
    }

    // Check if path contains Iceberg table
    isIcebergTablePath(path) {
        // More specific check - look for typical Iceberg table structure
        // Iceberg tables usually have /metadata/, /data/, and manifest files
        const pathParts = path.toLowerCase().split('/');
        const lastPart = pathParts[pathParts.length - 1];
        
        // Check if we're in a directory that's likely an Iceberg table root
        // This is a heuristic - we'd need to actually check for metadata.json files to be sure
        return false; // Disabled for now - too many false positives
    }

    // Parse Iceberg metadata JSON
    async parseMetadata(metadataJson) {
        try {
            const metadata = typeof metadataJson === 'string' ? JSON.parse(metadataJson) : metadataJson;
            
            return {
                formatVersion: metadata['format-version'],
                tableUuid: metadata['table-uuid'],
                location: metadata.location,
                lastUpdated: metadata['last-updated-ms'] ? new Date(metadata['last-updated-ms']) : null,
                lastColumnId: metadata['last-column-id'],
                schema: this.parseSchema(metadata.schema || metadata.schemas?.[metadata['current-schema-id']]),
                currentSnapshot: metadata['current-snapshot-id'],
                snapshots: this.parseSnapshots(metadata.snapshots || []),
                partitionSpecs: metadata['partition-specs'] || [],
                sortOrders: metadata['sort-orders'] || [],
                properties: metadata.properties || {},
                snapshotLog: metadata['snapshot-log'] || [],
                metadataLog: metadata['metadata-log'] || []
            };
        } catch (error) {
            console.error('Failed to parse Iceberg metadata:', error);
            return null;
        }
    }

    // Parse schema information
    parseSchema(schema) {
        if (!schema) return null;
        
        return {
            schemaId: schema['schema-id'],
            fields: this.parseFields(schema.fields || [])
        };
    }

    // Parse field definitions
    parseFields(fields) {
        return fields.map(field => ({
            id: field.id,
            name: field.name,
            required: field.required,
            type: this.parseType(field.type),
            doc: field.doc
        }));
    }

    // Parse type information
    parseType(type) {
        if (typeof type === 'string') {
            return { type: type };
        }
        
        if (type.type === 'struct') {
            return {
                type: 'struct',
                fields: this.parseFields(type.fields || [])
            };
        }
        
        if (type.type === 'list') {
            return {
                type: 'list',
                elementType: this.parseType(type['element-type'] || type.element)
            };
        }
        
        if (type.type === 'map') {
            return {
                type: 'map',
                keyType: this.parseType(type['key-type'] || type.key),
                valueType: this.parseType(type['value-type'] || type.value)
            };
        }
        
        return type;
    }

    // Parse snapshot information
    parseSnapshots(snapshots) {
        return snapshots.map(snapshot => ({
            snapshotId: snapshot['snapshot-id'],
            parentSnapshotId: snapshot['parent-snapshot-id'],
            sequenceNumber: snapshot['sequence-number'],
            timestamp: snapshot['timestamp-ms'] ? new Date(snapshot['timestamp-ms']) : null,
            manifestList: snapshot['manifest-list'],
            summary: snapshot.summary || {},
            schemaId: snapshot['schema-id']
        }));
    }

    // Format type for display
    formatType(type) {
        if (typeof type === 'string') {
            return type;
        }
        
        if (type.type === 'struct') {
            return 'struct<' + type.fields.map(f => `${f.name}:${this.formatType(f.type)}`).join(', ') + '>';
        }
        
        if (type.type === 'list') {
            return `list<${this.formatType(type.elementType)}>`;
        }
        
        if (type.type === 'map') {
            return `map<${this.formatType(type.keyType)}, ${this.formatType(type.valueType)}>`;
        }
        
        return type.type || JSON.stringify(type);
    }

    // Create HTML for metadata display
    createMetadataHTML(metadata) {
        if (!metadata) {
            return '<p class="text-red-600">Failed to parse Iceberg metadata</p>';
        }

        let html = `
            <div class="space-y-6">
                <!-- Overview -->
                <div>
                    <h4 class="font-semibold text-gray-900 mb-3">Table Overview</h4>
                    <dl class="grid grid-cols-1 gap-2 text-sm">
                        <div class="flex justify-between">
                            <dt class="text-gray-500">Format Version:</dt>
                            <dd class="font-medium">${metadata.formatVersion}</dd>
                        </div>
                        <div class="flex justify-between">
                            <dt class="text-gray-500">Table UUID:</dt>
                            <dd class="font-mono text-xs">${metadata.tableUuid}</dd>
                        </div>
                        <div class="flex justify-between">
                            <dt class="text-gray-500">Location:</dt>
                            <dd class="font-mono text-xs truncate" title="${metadata.location}">${metadata.location}</dd>
                        </div>
                        ${metadata.lastUpdated ? `
                        <div class="flex justify-between">
                            <dt class="text-gray-500">Last Updated:</dt>
                            <dd>${metadata.lastUpdated.toLocaleString()}</dd>
                        </div>
                        ` : ''}
                    </dl>
                </div>

                <!-- Schema -->
                ${metadata.schema ? `
                <div>
                    <h4 class="font-semibold text-gray-900 mb-3">Schema</h4>
                    <div class="overflow-x-auto">
                        <table class="min-w-full text-sm">
                            <thead>
                                <tr class="border-b border-gray-200">
                                    <th class="text-left py-2 pr-4 font-medium text-gray-700">Field</th>
                                    <th class="text-left py-2 pr-4 font-medium text-gray-700">Type</th>
                                    <th class="text-left py-2 font-medium text-gray-700">Required</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${metadata.schema.fields.map(field => `
                                    <tr class="border-b border-gray-100">
                                        <td class="py-2 pr-4 font-mono">${field.name}</td>
                                        <td class="py-2 pr-4 font-mono text-xs">${this.formatType(field.type)}</td>
                                        <td class="py-2">${field.required ? '✓' : ''}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
                ` : ''}

                <!-- Snapshots -->
                ${metadata.snapshots && metadata.snapshots.length > 0 ? `
                <div>
                    <h4 class="font-semibold text-gray-900 mb-3">Snapshot History</h4>
                    <div class="space-y-2">
                        ${metadata.snapshots.slice(-5).reverse().map(snapshot => `
                            <div class="p-3 bg-gray-50 rounded-lg text-sm ${snapshot.snapshotId === metadata.currentSnapshot ? 'ring-2 ring-primary' : ''}">
                                <div class="flex justify-between items-start">
                                    <div>
                                        <span class="font-mono">${snapshot.snapshotId}</span>
                                        ${snapshot.snapshotId === metadata.currentSnapshot ? '<span class="ml-2 text-xs bg-primary text-white px-2 py-1 rounded">CURRENT</span>' : ''}
                                    </div>
                                    <span class="text-gray-500 text-xs">${snapshot.timestamp ? snapshot.timestamp.toLocaleString() : 'Unknown'}</span>
                                </div>
                                ${snapshot.summary && snapshot.summary['added-files-size'] ? `
                                <div class="mt-1 text-xs text-gray-600">
                                    Added: ${this.formatBytes(parseInt(snapshot.summary['added-files-size']))} in ${snapshot.summary['added-data-files'] || 0} files
                                </div>
                                ` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}

                <!-- Partitions -->
                ${metadata.partitionSpecs && metadata.partitionSpecs.length > 0 && metadata.partitionSpecs[0].fields.length > 0 ? `
                <div>
                    <h4 class="font-semibold text-gray-900 mb-3">Partitioning</h4>
                    <div class="space-y-2">
                        ${metadata.partitionSpecs.map(spec => `
                            <div class="text-sm">
                                <span class="text-gray-500">Spec ${spec['spec-id']}:</span>
                                ${spec.fields.map(field => `
                                    <span class="ml-2 font-mono">${field.name} (${field.transform})</span>
                                `).join(', ')}
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}
            </div>
        `;

        return html;
    }

    // Format bytes to human readable
    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Detect table in path
    detectTableFromPath(path) {
        // Common Iceberg table patterns
        const patterns = [
            /(.+)\/(metadata|data|snapshots)/, // table_name/metadata/
            /(.+)\.db\/([^\/]+)/, // database.db/table_name/
            /warehouse\/([^\/]+)\/([^\/]+)/ // warehouse/database/table/
        ];

        for (const pattern of patterns) {
            const match = path.match(pattern);
            if (match) {
                return {
                    database: match[1] ? match[1].split('/').slice(-2, -1)[0] : null,
                    table: match[1] ? match[1].split('/').slice(-1)[0] : match[2]
                };
            }
        }

        return null;
    }
}

// Export for use in browser
window.IcebergMetadataParser = IcebergMetadataParser;