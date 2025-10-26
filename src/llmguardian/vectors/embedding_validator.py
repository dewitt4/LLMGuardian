"""
vectors/embedding_validator.py - Embedding validation and security
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from ..core.exceptions import ValidationError
from ..core.logger import SecurityLogger


@dataclass
class EmbeddingMetadata:
    """Metadata for embeddings"""

    dimension: int
    model: str
    timestamp: datetime
    source: str
    checksum: str


@dataclass
class ValidationResult:
    """Result of embedding validation"""

    is_valid: bool
    errors: List[str]
    normalized_embedding: Optional[np.ndarray]
    metadata: Dict[str, Any]


class EmbeddingValidator:
    """Validates and secures embeddings"""

    def __init__(self, security_logger: Optional[SecurityLogger] = None):
        self.security_logger = security_logger
        self.known_models = {
            "openai-ada-002": 1536,
            "openai-text-embedding-ada-002": 1536,
            "huggingface-bert-base": 768,
            "huggingface-mpnet-base": 768,
        }
        self.max_dimension = 2048
        self.min_dimension = 64

    def validate_embedding(
        self, embedding: np.ndarray, metadata: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Validate an embedding vector"""
        try:
            errors = []

            # Check dimensions
            if embedding.ndim != 1:
                errors.append("Embedding must be a 1D vector")

            if len(embedding) > self.max_dimension:
                errors.append(
                    f"Embedding dimension exceeds maximum {self.max_dimension}"
                )

            if len(embedding) < self.min_dimension:
                errors.append(f"Embedding dimension below minimum {self.min_dimension}")

            # Check for NaN or Inf values
            if np.any(np.isnan(embedding)) or np.any(np.isinf(embedding)):
                errors.append("Embedding contains NaN or Inf values")

            # Validate against known models
            if metadata and "model" in metadata:
                if metadata["model"] in self.known_models:
                    expected_dim = self.known_models[metadata["model"]]
                    if len(embedding) != expected_dim:
                        errors.append(
                            f"Dimension mismatch for model {metadata['model']}: "
                            f"expected {expected_dim}, got {len(embedding)}"
                        )

            # Normalize embedding
            normalized = None
            if not errors:
                normalized = self._normalize_embedding(embedding)

                # Calculate checksum
                checksum = self._calculate_checksum(normalized)

                # Create metadata
                embedding_metadata = EmbeddingMetadata(
                    dimension=len(embedding),
                    model=metadata.get("model", "unknown") if metadata else "unknown",
                    timestamp=datetime.utcnow(),
                    source=metadata.get("source", "unknown") if metadata else "unknown",
                    checksum=checksum,
                )

            result = ValidationResult(
                is_valid=len(errors) == 0,
                errors=errors,
                normalized_embedding=normalized,
                metadata=vars(embedding_metadata) if not errors else {},
            )

            if errors and self.security_logger:
                self.security_logger.log_security_event(
                    "embedding_validation_failure", errors=errors, metadata=metadata
                )

            return result

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "embedding_validation_error", error=str(e)
                )
            raise ValidationError(f"Embedding validation failed: {str(e)}")

    def _normalize_embedding(self, embedding: np.ndarray) -> np.ndarray:
        """Normalize embedding vector"""
        norm = np.linalg.norm(embedding)
        if norm > 0:
            return embedding / norm
        return embedding

    def _calculate_checksum(self, embedding: np.ndarray) -> str:
        """Calculate checksum for embedding"""
        return hashlib.sha256(embedding.tobytes()).hexdigest()

    def check_similarity(self, embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """Check similarity between two embeddings"""
        try:
            # Validate both embeddings
            result1 = self.validate_embedding(embedding1)
            result2 = self.validate_embedding(embedding2)

            if not result1.is_valid or not result2.is_valid:
                raise ValidationError("Invalid embeddings for similarity check")

            # Calculate cosine similarity
            return float(
                np.dot(result1.normalized_embedding, result2.normalized_embedding)
            )

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "similarity_check_error", error=str(e)
                )
            raise ValidationError(f"Similarity check failed: {str(e)}")

    def detect_anomalies(
        self, embeddings: List[np.ndarray], threshold: float = 0.8
    ) -> List[int]:
        """Detect anomalous embeddings in a set"""
        try:
            anomalies = []

            # Validate all embeddings
            valid_embeddings = []
            for i, emb in enumerate(embeddings):
                result = self.validate_embedding(emb)
                if result.is_valid:
                    valid_embeddings.append(result.normalized_embedding)
                else:
                    anomalies.append(i)

            if not valid_embeddings:
                return list(range(len(embeddings)))

            # Calculate mean embedding
            mean_embedding = np.mean(valid_embeddings, axis=0)
            mean_embedding = self._normalize_embedding(mean_embedding)

            # Check similarities
            for i, emb in enumerate(valid_embeddings):
                similarity = float(np.dot(emb, mean_embedding))
                if similarity < threshold:
                    anomalies.append(i)

            if anomalies and self.security_logger:
                self.security_logger.log_security_event(
                    "anomalous_embeddings_detected",
                    count=len(anomalies),
                    total_embeddings=len(embeddings),
                )

            return anomalies

        except Exception as e:
            if self.security_logger:
                self.security_logger.log_security_event(
                    "anomaly_detection_error", error=str(e)
                )
            raise ValidationError(f"Anomaly detection failed: {str(e)}")

    def add_known_model(self, model_name: str, dimension: int):
        """Add a known model to the validator"""
        self.known_models[model_name] = dimension

    def verify_metadata(self, metadata: Dict[str, Any]) -> bool:
        """Verify embedding metadata"""
        required_fields = {"model", "dimension", "timestamp"}
        return all(field in metadata for field in required_fields)
