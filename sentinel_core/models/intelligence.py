#!/usr/bin/env python3
"""
Normalized Intelligence Data Model
Canonical schema for entities, observables, relationships, and evidence
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass, asdict, field


class EntityType(Enum):
    """Core entity types"""
    DOMAIN = "domain"
    IP = "ip"
    ASN = "asn"
    EMAIL = "email"
    CERTIFICATE = "certificate"
    PERSON = "person"
    ORGANIZATION = "organization"
    MALWARE_FAMILY = "malware_family"
    CVE = "cve"
    IOC = "ioc"
    URL = "url"
    HASH = "hash"
    JA3 = "ja3"
    USER_AGENT = "user_agent"
    TTP = "ttp"  # MITRE ATT&CK Technique
    PHONE = "phone"
    USERNAME = "username"


class RelationshipType(Enum):
    """Relationship types between entities"""
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    OWNED_BY = "owned_by"
    ASSOCIATED_WITH = "associated_with"
    COMMUNICATES_WITH = "communicates_with"
    DROPS = "drops"
    USES = "uses"
    TARGETS = "targets"
    MITIGATES = "mitigates"
    INDICATES = "indicates"
    ATTRIBUTED_TO = "attributed_to"
    REGISTERED_WITH = "registered_with"
    ISSUED_BY = "issued_by"
    CONTAINS = "contains"
    SIMILAR_TO = "similar_to"
    DERIVED_FROM = "derived_from"


class ConfidenceLevel(Enum):
    """Confidence scoring"""
    VERY_LOW = 10
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    VERY_HIGH = 90
    CERTAIN = 100


class SourceReliability(Enum):
    """Source reliability rating"""
    COMPLETELY_RELIABLE = "A"
    USUALLY_RELIABLE = "B"
    FAIRLY_RELIABLE = "C"
    NOT_USUALLY_RELIABLE = "D"
    UNRELIABLE = "E"
    RELIABILITY_UNKNOWN = "F"


@dataclass
class Entity:
    """Base entity class"""
    id: str
    entity_type: str
    value: str
    created_at: str
    updated_at: str
    
    # Metadata
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    confidence: int = ConfidenceLevel.MEDIUM.value
    source_reliability: str = SourceReliability.RELIABILITY_UNKNOWN.value
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Entity':
        return cls(**data)
    
    def add_tag(self, tag: str):
        if tag not in self.tags:
            self.tags.append(tag)
    
    def update_confidence(self, new_confidence: int):
        self.confidence = max(0, min(100, new_confidence))
        self.updated_at = datetime.now().isoformat()


@dataclass
class Relationship:
    """Relationship between two entities"""
    id: str
    source_entity_id: str
    target_entity_id: str
    relationship_type: str
    created_at: str
    
    # Temporal bounds
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    
    # Metadata
    confidence: int = ConfidenceLevel.MEDIUM.value
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Relationship':
        return cls(**data)


@dataclass
class Evidence:
    """Evidence object linking raw data to entities"""
    id: str
    entity_id: str
    source_type: str  # api, file, scan, manual
    source_name: str  # e.g., 'crtsh', 'shodan', 'manual_entry'
    raw_data: Dict[str, Any]
    collected_at: str
    
    # Provenance
    collector_version: Optional[str] = None
    source_url: Optional[str] = None
    extraction_method: Optional[str] = None
    
    # Integrity
    hash: Optional[str] = None
    chain_of_custody: List[Dict[str, Any]] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.hash:
            self.hash = self._compute_hash()
    
    def _compute_hash(self) -> str:
        """Compute SHA256 hash of raw data for integrity"""
        data_str = json.dumps(self.raw_data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def add_custody_event(self, action: str, actor: str, timestamp: str = None):
        self.chain_of_custody.append({
            'action': action,
            'actor': actor,
            'timestamp': timestamp or datetime.now().isoformat()
        })
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Observable:
    """IOC Observable with typing"""
    id: str
    observable_type: str  # hash, url, ja3, etc.
    value: str
    created_at: str
    
    # Classification
    malware_family: Optional[str] = None
    threat_type: Optional[str] = None
    tlps: str = "GREEN"  # TLP marking
    
    # Detection
    detection_ratio: Optional[int] = None  # e.g., 45/70 AV engines
    total_engines: Optional[int] = None
    
    # Metadata
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    sighting_count: int = 1
    confidence: int = ConfidenceLevel.MEDIUM.value
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IntelligenceGraph:
    """Graph-based intelligence store for link analysis"""
    
    def __init__(self):
        self.entities: Dict[str, Entity] = {}
        self.relationships: Dict[str, Relationship] = {}
        self.evidence: Dict[str, Evidence] = {}
        self.observables: Dict[str, Observable] = {}
    
    def add_entity(self, entity: Entity) -> str:
        """Add or update an entity"""
        # Check for existing entity with same type+value
        existing = self.find_entity(entity.entity_type, entity.value)
        if existing:
            # Merge: update last_seen, increase confidence
            existing.last_seen = entity.last_seen or datetime.now().isoformat()
            existing.updated_at = datetime.now().isoformat()
            existing.confidence = min(100, existing.confidence + 5)
            if entity.source_reliability == SourceReliability.COMPLETELY_RELIABLE.value:
                existing.confidence = min(100, existing.confidence + 10)
            return existing.id
        
        self.entities[entity.id] = entity
        return entity.id
    
    def add_relationship(self, relationship: Relationship) -> str:
        """Add a relationship between entities"""
        self.relationships[relationship.id] = relationship
        return relationship.id
    
    def add_evidence(self, evidence: Evidence) -> str:
        """Add evidence linked to an entity"""
        self.evidence[evidence.id] = evidence
        return evidence.id
    
    def add_observable(self, observable: Observable) -> str:
        """Add an IOC observable"""
        self.observables[observable.id] = observable
        return observable.id
    
    def find_entity(self, entity_type: str, value: str) -> Optional[Entity]:
        """Find entity by type and value (fuzzy matching for some types)"""
        for entity in self.entities.values():
            if entity.entity_type != entity_type:
                continue
            
            # Exact match for most types
            if entity.value.lower() == value.lower():
                return entity
            
            # Fuzzy matching for domains (handle www. prefix)
            if entity_type == EntityType.DOMAIN.value:
                norm_entity = entity.value.lower().lstrip('www.')
                norm_value = value.lower().lstrip('www.')
                if norm_entity == norm_value:
                    return entity
        
        return None
    
    def get_entity_relationships(self, entity_id: str) -> List[Relationship]:
        """Get all relationships for an entity"""
        related = []
        for rel in self.relationships.values():
            if rel.source_entity_id == entity_id or rel.target_entity_id == entity_id:
                related.append(rel)
        return related
    
    def find_path(self, source_id: str, target_id: str, max_depth: int = 3) -> List[List[str]]:
        """Find paths between two entities (BFS)"""
        from collections import deque
        
        if source_id == target_id:
            return [[source_id]]
        
        visited = {source_id}
        queue = deque([(source_id, [source_id])])
        paths = []
        
        while queue and len(paths) < 10:  # Limit paths returned
            current, path = queue.popleft()
            
            if len(path) > max_depth:
                continue
            
            for rel in self.get_entity_relationships(current):
                next_id = rel.target_entity_id if rel.source_entity_id == current else rel.source_entity_id
                
                if next_id == target_id:
                    paths.append(path + [next_id])
                elif next_id not in visited:
                    visited.add(next_id)
                    queue.append((next_id, path + [next_id]))
        
        return paths
    
    def get_infrastructure_overlap(self, entity_ids: List[str]) -> Dict[str, Any]:
        """Find shared infrastructure between entities"""
        shared = {}
        
        # Get all connected entities
        connections = {}
        for eid in entity_ids:
            connections[eid] = set()
            for rel in self.get_entity_relationships(eid):
                other = rel.target_entity_id if rel.source_entity_id == eid else rel.source_entity_id
                connections[eid].add(other)
        
        # Find overlaps
        for i, id1 in enumerate(entity_ids):
            for id2 in entity_ids[i+1:]:
                overlap = connections[id1] & connections[id2]
                if overlap:
                    key = f"{id1}-{id2}"
                    shared[key] = {
                        'entity1': id1,
                        'entity2': id2,
                        'shared_infrastructure': list(overlap),
                        'count': len(overlap)
                    }
        
        return shared
    
    def to_dict(self) -> Dict[str, Any]:
        """Export graph to dictionary"""
        return {
            'entities': {k: v.to_dict() for k, v in self.entities.items()},
            'relationships': {k: v.to_dict() for k, v in self.relationships.items()},
            'evidence': {k: v.to_dict() for k, v in self.evidence.items()},
            'observables': {k: v.to_dict() for k, v in self.observables.items()}
        }
    
    def export_stix(self) -> Dict[str, Any]:
        """Export to STIX 2.1 format"""
        stix_objects = []
        
        for entity in self.entities.values():
            stix_obj = {
                'type': 'indicator' if entity.entity_type in ['ioc', 'hash', 'url'] else 'identity',
                'spec_version': '2.1',
                'id': f"indicator--{entity.id}" if entity.entity_type in ['ioc', 'hash', 'url'] else f"identity--{entity.id}",
                'created': entity.created_at,
                'modified': entity.updated_at,
                'name': entity.value,
                'confidence': entity.confidence,
                'labels': entity.tags
            }
            stix_objects.append(stix_obj)
        
        return {
            'type': 'bundle',
            'id': f"bundle--{hashlib.md5(str(datetime.now()).encode()).hexdigest()}",
            'objects': stix_objects
        }


# Factory functions
def create_entity(entity_type: EntityType, value: str, **kwargs) -> Entity:
    """Factory function to create entities"""
    now = datetime.now().isoformat()
    return Entity(
        id=f"{entity_type.value}_{hashlib.md5(value.encode()).hexdigest()[:12]}",
        entity_type=entity_type.value,
        value=value,
        created_at=now,
        updated_at=now,
        first_seen=kwargs.get('first_seen', now),
        last_seen=kwargs.get('last_seen', now),
        confidence=kwargs.get('confidence', ConfidenceLevel.MEDIUM.value),
        source_reliability=kwargs.get('source_reliability', SourceReliability.RELIABILITY_UNKNOWN.value),
        tags=kwargs.get('tags', []),
        metadata=kwargs.get('metadata', {})
    )


def create_relationship(source: Entity, target: Entity, 
                       rel_type: RelationshipType, **kwargs) -> Relationship:
    """Factory function to create relationships"""
    now = datetime.now().isoformat()
    return Relationship(
        id=f"rel_{hashlib.md5(f'{source.id}{target.id}{rel_type.value}'.encode()).hexdigest()[:12]}",
        source_entity_id=source.id,
        target_entity_id=target.id,
        relationship_type=rel_type.value,
        created_at=now,
        first_seen=kwargs.get('first_seen', now),
        last_seen=kwargs.get('last_seen', now),
        confidence=kwargs.get('confidence', ConfidenceLevel.MEDIUM.value),
        weight=kwargs.get('weight', 1.0),
        metadata=kwargs.get('metadata', {})
    )


if __name__ == '__main__':
    # Test the data model
    graph = IntelligenceGraph()
    
    # Create test entities
    domain = create_entity(EntityType.DOMAIN, "example.com", tags=['test'])
    ip = create_entity(EntityType.IP, "93.184.216.34")
    
    # Add to graph
    domain_id = graph.add_entity(domain)
    ip_id = graph.add_entity(ip)
    
    # Create relationship
    rel = create_relationship(domain, ip, RelationshipType.RESOLVES_TO)
    graph.add_relationship(rel)
    
    print(json.dumps(graph.to_dict(), indent=2))
