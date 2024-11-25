# LLMGuardian Vectors Package

The Vectors package provides comprehensive security tools for handling vector embeddings, RAG (Retrieval-Augmented Generation) operations, and vector storage. It addresses key security concerns outlined in the OWASP Top 10 for LLM applications, particularly focusing on vector and embedding weaknesses (LLM08).

## Components

### 1. Embedding Validator (`embedding_validator.py`)
Validates and secures embedding vectors against manipulation and attacks.

```python
from llmguardian.vectors import EmbeddingValidator

# Initialize validator
validator = EmbeddingValidator()

# Validate embedding
result = validator.validate_embedding(
    embedding=your_embedding,
    metadata={
        "model": "openai-ada-002",
        "source": "user_documents"
    }
)

if result.is_valid:
    normalized_embedding = result.normalized_embedding
    print(f"Embedding metadata: {result.metadata}")
else:
    print(f"Validation errors: {result.errors}")
```

Key Features:
- Dimension validation
- Model compatibility checks
- Normalization
- Anomaly detection
- Checksum verification

### 2. Vector Scanner (`vector_scanner.py`)
Scans vector databases for security vulnerabilities and potential attacks.

```python
from llmguardian.vectors import VectorScanner
from llmguardian.vectors.vector_scanner import ScanTarget, VulnerabilityReport

# Initialize scanner
scanner = VectorScanner()

# Create scan target
target = ScanTarget(
    vectors=your_vectors,
    metadata=vector_metadata,
    source="vector_db"
)

# Perform scan
result = scanner.scan_vectors(target)

if result.vulnerabilities:
    for vuln in result.vulnerabilities:
        print(f"Type: {vuln.vulnerability_type}")
        print(f"Severity: {vuln.severity}")
        print(f"Recommendations: {vuln.recommendations}")
```

Key Features:
- Poisoning detection
- Malicious payload scanning
- Data leakage detection
- Clustering attack detection
- Index manipulation checks

### 3. Retrieval Guard (`retrieval_guard.py`)
Secures RAG operations and protects against retrieval-based attacks.

```python
from llmguardian.vectors import RetrievalGuard
from llmguardian.vectors.retrieval_guard import RetrievalContext

# Initialize guard
guard = RetrievalGuard()

# Create context
context = RetrievalContext(
    query_embedding=query_emb,
    retrieved_embeddings=retrieved_embs,
    retrieved_content=retrieved_texts,
    metadata={"source": "knowledge_base"}
)

# Check retrieval
result = guard.check_retrieval(context)

if not result.is_safe:
    print(f"Detected risks: {result.risks}")
    print(f"Failed checks: {result.checks_failed}")
    # Use filtered content
    safe_content = result.filtered_content
```

Key Features:
- Relevance validation
- Context injection detection
- Content filtering
- Privacy protection
- Chunking validation

### 4. Storage Validator (`storage_validator.py`)
Validates vector storage security and integrity.

```python
from llmguardian.vectors import StorageValidator
from llmguardian.vectors.storage_validator import StorageMetadata

# Initialize validator
validator = StorageValidator()

# Create metadata
metadata = StorageMetadata(
    storage_type="vector_db",
    vector_count=1000,
    dimension=1536,
    created_at=datetime.utcnow(),
    updated_at=datetime.utcnow(),
    version="1.0.0",
    checksum="...",
    encryption_info={"algorithm": "AES-256-GCM"}
)

# Validate storage
result = validator.validate_storage(
    metadata=metadata,
    vectors=your_vectors,
    context={"authentication": "enabled"}
)

if not result.is_valid:
    print(f"Risks detected: {result.risks}")
    print(f"Violations: {result.violations}")
    print(f"Recommendations: {result.recommendations}")
```

Key Features:
- Access control validation
- Data integrity checks
- Index security validation
- Version control checks
- Encryption validation

## Installation

```bash
pip install llmguardian
```

For development:
```bash
pip install -r requirements/dev.txt
```

## Best Practices

### 1. Embedding Security
- Validate all embeddings before storage
- Monitor for anomalies
- Implement proper normalization
- Maintain model compatibility
- Regular integrity checks

### 2. Vector Database Security
- Regular security scans
- Monitor for poisoning attempts
- Implement access controls
- Secure indexing mechanisms
- Data integrity validation

### 3. RAG Security
- Validate all retrievals
- Monitor relevance scores
- Implement content filtering
- Protect against injection
- Secure chunking mechanisms

### 4. Storage Security
- Enable encryption
- Regular backups
- Version control
- Access logging
- Integrity monitoring

## Integration Example

Here's how to integrate all vector security components:

```python
from llmguardian.vectors import (
    EmbeddingValidator,
    VectorScanner,
    RetrievalGuard,
    StorageValidator
)

class SecureVectorSystem:
    def __init__(self):
        self.embedding_validator = EmbeddingValidator()
        self.vector_scanner = VectorScanner()
        self.retrieval_guard = RetrievalGuard()
        self.storage_validator = StorageValidator()

    async def secure_rag_operation(
        self,
        query_embedding: np.ndarray,
        knowledge_base: Dict[str, Any]
    ) -> List[str]:
        try:
            # 1. Validate query embedding
            query_result = self.embedding_validator.validate_embedding(
                query_embedding,
                metadata={"source": "user_query"}
            )
            if not query_result.is_valid:
                raise SecurityError("Invalid query embedding")

            # 2. Scan vector database
            scan_result = self.vector_scanner.scan_vectors(
                ScanTarget(
                    vectors=knowledge_base["vectors"],
                    metadata=knowledge_base["metadata"]
                )
            )
            if scan_result.vulnerabilities:
                self._handle_vulnerabilities(scan_result.vulnerabilities)

            # 3. Perform and guard retrieval
            retrieval_result = self.retrieval_guard.check_retrieval(
                RetrievalContext(
                    query_embedding=query_result.normalized_embedding,
                    retrieved_embeddings=retrieved_embeddings,
                    retrieved_content=retrieved_texts
                )
            )

            # 4. Validate storage
            storage_result = self.storage_validator.validate_storage(
                metadata=storage_metadata,
                vectors=knowledge_base["vectors"]
            )
            if not storage_result.is_valid:
                self._handle_storage_issues(storage_result)

            return retrieval_result.filtered_content

        except Exception as e:
            logger.error(f"Secure RAG operation failed: {str(e)}")
            raise
```

## Security Considerations

1. **Embedding Security**
   - Validate dimensions
   - Check for anomalies
   - Monitor for poisoning
   - Implement integrity checks

2. **Vector Database Security**
   - Regular scanning
   - Access control
   - Integrity validation
   - Backup strategy

3. **RAG Security**
   - Content validation
   - Query inspection
   - Result filtering
   - Context protection

4. **Storage Security**
   - Encryption
   - Access controls
   - Version management
   - Regular validation

### Testing
```bash
# Run vector package tests
pytest tests/vectors/

# Run specific test file
pytest tests/vectors/test_embedding_validator.py
```