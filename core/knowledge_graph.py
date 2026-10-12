# core/knowledge_graph.py
#
# Asset-Oriented Sequential Attack Knowledge Graph
# Formalism: Wachter 2023 (arXiv:2311.10050) + Konsta et al. 2024
# Generation: vulnerability-driven, runtime (incrementally populated by AKG tools)
#
# The graph is a Labeled Property Graph (LPG):
#   - Nodes: typed entities (Host, Service, Interface, Subnet, ExploitStep, Credential)
#   - Edges: typed directed relationships (RUNS, EXPLOITED_VIA, COMPROMISES, YIELDS, ...)
#   - Each node/edge carries: source ("tool" | "model"), provenance, properties
#
# Persistence: JSON file at campaigns/<campaign_id>/graph.json
# Thread-safety: single-process, asyncio-compatible (no locks needed for sequential writes)

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

# ── Type aliases ──────────────────────────────────────────────────────────────

NodeType  = Literal["Host", "Service", "Interface", "Subnet", "ExploitStep", "Credential"]
EdgeType  = Literal[
    "CONTAINS", "HAS_INTERFACE", "CONNECTS_TO",
    "RUNS", "EXPLOITED_VIA", "COMPROMISES", "YIELDS", "PIVOTS_INTO",
]
Source    = Literal["tool", "model"]

# ── Dataclasses ───────────────────────────────────────────────────────────────


@dataclass
class Provenance:
    """Links a graph element to the concrete tool call that created it."""
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    timestamp: str = field(default_factory=lambda: _now())


@dataclass
class GraphNode:
    id:           str
    type:         NodeType
    label:        str
    source:       Source
    discovered_at: str = field(default_factory=lambda: _now())
    provenance:   Provenance | None = None
    properties:   dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "id":           self.id,
            "type":         self.type,
            "label":        self.label,
            "source":       self.source,
            "discovered_at": self.discovered_at,
            "properties":   self.properties,
        }
        if self.provenance:
            d["provenance"] = {
                "tool":       self.provenance.tool,
                "args":       self.provenance.args,
                "raw_output": self.provenance.raw_output,
                "timestamp":  self.provenance.timestamp,
            }
        return d


@dataclass
class GraphEdge:
    id:         str
    type:       EdgeType
    from_node:  str       # node id
    to_node:    str       # node id
    source:     Source
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "type":       self.type,
            "from":       self.from_node,
            "to":         self.to_node,
            "source":     self.source,
            "properties": self.properties,
        }


@dataclass
class EventLogEntry:
    seq:       int
    timestamp: str
    type:      str          # reconnaissance | exploitation | post_exploitation | credential_found | pivot | decision
    actor:     str          # orchestrator | scout | coder | post_exploiter
    source:    Source
    action:    str          # tool name or decision keyword
    target:    str | None
    reasoning: str | None   # only for source="model"
    result:    str

    def to_dict(self) -> dict:
        return {
            "seq":       self.seq,
            "timestamp": self.timestamp,
            "type":      self.type,
            "actor":     self.actor,
            "source":    self.source,
            "action":    self.action,
            "target":    self.target,
            "reasoning": self.reasoning,
            "result":    self.result,
        }


# ── AttackGraph ───────────────────────────────────────────────────────────────


class AttackGraph:
    """
    In-memory representation of the campaign's Attack Knowledge Graph.
    Automatically persisted to graph.json after every mutation.
    """

    # Graph formalism meta
    FORMALISM   = "Asset-Oriented Sequential Attack Graph"
    GENERATION  = "vulnerability-driven, runtime"
    REFERENCES  = [
        "Wachter 2023 – Graph models for Cybersecurity: A Survey (arXiv:2311.10050)",
        "Konsta et al. 2024 – Survey: Automatic generation of attack trees and attack graphs (Computers & Security)",
    ]

    def __init__(self, campaign_id: str, campaign_dir: str = "campaigns"):
        self.campaign_id    = campaign_id
        self._path          = Path(campaign_dir) / campaign_id / "graph.json"
        self._nodes:      dict[str, GraphNode]  = {}
        self._edges:      dict[str, GraphEdge]  = {}
        self._event_log:  list[EventLogEntry]   = []
        self._created_at  = _now()
        self._updated_at  = _now()
        self._lock        = threading.RLock()
        # IP → node_id index: maps every known IP address to its canonical node id.
        # Populated for Host nodes (ip property) and Interface nodes (iface_ip property).
        # Used by add_host() to prevent duplicate nodes for the same IP.
        self._ip_index:   dict[str, str]        = {}

    # ── Public node API ───────────────────────────────────────────────────────

    def add_node(self, node: GraphNode) -> GraphNode:
        """Add or silently skip a duplicate node (idempotent by id). Updates IP index."""
        with self._lock:
            if node.id in self._nodes:
                return self._nodes[node.id]   # already present — skip
            self._nodes[node.id] = node
            # Keep IP index up to date
            if node.type == "Host":
                ip = node.properties.get("ip", "")
                if ip:
                    self._ip_index[ip] = node.id
            elif node.type == "Interface":
                iface_ip = node.properties.get("ip", "")
                if iface_ip and iface_ip not in self._ip_index:
                    # Interface IP only goes into index if no Host claimed it first
                    self._ip_index[iface_ip] = node.id
            self._touch()
            self._save()
            return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        """Add or silently skip a duplicate edge."""
        with self._lock:
            return self._safe_add_edge(edge)

    def _safe_add_edge(self, edge: GraphEdge) -> GraphEdge:
        """Internal edge insertion — caller must already hold self._lock."""
        if edge.id in self._edges:
            return self._edges[edge.id]
        self._edges[edge.id] = edge
        self._touch()
        self._save()
        return edge

    def log_event(self, entry: EventLogEntry) -> None:
        with self._lock:
            self._event_log.append(entry)
            self._touch()
            self._save()

    def delete_node(self, node_id: str, cascade_children: bool = True) -> bool:
        """
        Deletes a node and its connected edges from the graph.
        If an ExploitStep node is deleted, resets the target host's exploit_status to 'pending'.
        If a Host node is deleted and cascade_children is True, also deletes its services and interfaces.
        """
        with self._lock:
            if node_id not in self._nodes:
                return False

            node = self._nodes[node_id]
            nodes_to_delete = [node_id]

            if node.type == "Host":
                ip = node.properties.get("ip", "")
                if ip and self._ip_index.get(ip) == node_id:
                    del self._ip_index[ip]
                if cascade_children:
                    # Find child services and interfaces
                    for nid, n in list(self._nodes.items()):
                        if n.type == "Service" and (nid.startswith(f"svc-{ip}-") or f"-{ip}-" in nid):
                            nodes_to_delete.append(nid)
                        elif n.type == "Interface" and (nid.startswith(f"iface-{ip}-") or f"-{ip}-" in nid):
                            nodes_to_delete.append(nid)
                            iface_ip = n.properties.get("ip", "")
                            if iface_ip and self._ip_index.get(iface_ip) == nid:
                                del self._ip_index[iface_ip]
            elif node.type == "Interface":
                iface_ip = node.properties.get("ip", "")
                if iface_ip and self._ip_index.get(iface_ip) == node_id:
                    del self._ip_index[iface_ip]
            elif node.type == "ExploitStep":
                # Find connected compromised host and reset its status
                for edge in list(self._edges.values()):
                    if edge.type == "COMPROMISES" and edge.from_node == node_id:
                        host_node = self._nodes.get(edge.to_node)
                        if host_node and host_node.type == "Host":
                            host_node.properties["status"] = "alive"
                            host_node.properties["exploit_status"] = "pending"
                            host_node.properties["postexploit_status"] = "pending"
                    elif edge.type == "EXPLOITED_VIA" and edge.to_node == node_id:
                        svc_node = self._nodes.get(edge.from_node)
                        if svc_node and svc_node.type == "Service":
                            svc_node.properties["status"] = "open"

            # 1. Delete connected edges for all targeted nodes
            edges_to_del = [
                eid for eid, edge in self._edges.items()
                if edge.from_node in nodes_to_delete or edge.to_node in nodes_to_delete
            ]
            for eid in edges_to_del:
                del self._edges[eid]

            # 2. Delete the nodes
            for nid in nodes_to_delete:
                if nid in self._nodes:
                    del self._nodes[nid]

            self._touch()
            self._save()
            return True

    def delete_event(self, seq: int) -> bool:
        """
        Deletes an event log / decision entry by its sequence number.
        """
        with self._lock:
            initial_len = len(self._event_log)
            self._event_log = [ev for ev in self._event_log if ev.seq != int(seq)]
            if len(self._event_log) != initial_len:
                self._touch()
                self._save()
                return True
            return False

    def _resolve_canonical_host_id(self, ip: str) -> str:
        """
        Dato un IP, restituisce l'ID canonico del nodo Host ad esso associato.
        Se l'IP è noto come interfaccia di un host esistente, restituisce l'ID di quell'host.
        Altrimenti, restituisce il default 'host-{ip}'.
        """
        if ip in self._ip_index:
            node_id = self._ip_index[ip]
            node = self._nodes.get(node_id)
            if node:
                if node.type == "Host":
                    return node.id
                elif node.type == "Interface":
                    # Cerca l'host genitore di questa interfaccia tramite l'arco HAS_INTERFACE
                    for edge in self._edges.values():
                        if edge.type == "HAS_INTERFACE" and edge.to_node == node.id:
                            return edge.from_node
                    # Fallback provando ad estrarre l'host_ip dal node_id (iface-{host_ip}-{iface_name})
                    parts = node.id.split("-")
                    if len(parts) >= 2:
                        return f"host-{parts[1]}"
        return f"host-{ip}"

    def _resolve_subnet_id(self, target_cidr: str) -> str:
        """
        Finds the ID of the existing Subnet node that overlaps with/contains the given CIDR.
        If no such subnet is found, falls back to the default ID for the given CIDR.
        """
        import ipaddress
        try:
            target_net = ipaddress.ip_network(target_cidr, strict=False)
        except ValueError:
            return f"subnet-{target_cidr.replace('/', '_')}"

        with self._lock:
            for node in self._nodes.values():
                if node.type == "Subnet":
                    existing_cidr = node.properties.get("cidr")
                    if existing_cidr:
                        try:
                            existing_net = ipaddress.ip_network(existing_cidr, strict=False)
                            if target_net.overlaps(existing_net):
                                return node.id
                        except ValueError:
                            continue
            return f"subnet-{target_cidr.replace('/', '_')}"


    def _merge_hosts(self, source_host_id: str, target_host_id: str) -> None:
        """
        Unisca un host temporaneo (es. host-172.30.0.5) in un host canonico (es. host-172.28.0.5).
        Reindirizza tutti gli archi e cancella il nodo temporaneo.
        """
        if source_host_id not in self._nodes or target_host_id not in self._nodes:
            return

        print(f"[AKG] Merged temporary host {source_host_id} into canonical host {target_host_id}")

        # 1. Trova ed aggiorna gli archi collegati a source_host_id
        edges_to_modify = []
        for edge in list(self._edges.values()):
            if edge.from_node == source_host_id or edge.to_node == source_host_id:
                edges_to_modify.append(edge)

        source_ip_str = source_host_id.replace("host-", "")
        target_ip_str = target_host_id.replace("host-", "")

        for edge in edges_to_modify:
            if edge.id in self._edges:
                del self._edges[edge.id]

            new_from = target_host_id if edge.from_node == source_host_id else edge.from_node
            new_to   = target_host_id if edge.to_node == source_host_id else edge.to_node

            # Genera un ID per l'arco basato sui nuovi endpoint
            new_id = edge.id.replace(source_ip_str, target_ip_str)
            
            # Se l'arco esiste già con questo ID, non lo duplica
            new_edge = GraphEdge(
                id=new_id, type=edge.type, from_node=new_from, to_node=new_to,
                source=edge.source, properties=edge.properties
            )
            self._edges[new_id] = new_edge

        # 2. Aggiorna lo stato di pwned e la timestamp di scoperta più remota
        src_node = self._nodes[source_host_id]
        tgt_node = self._nodes[target_host_id]
        if src_node.discovered_at and (not tgt_node.discovered_at or src_node.discovered_at < tgt_node.discovered_at):
            tgt_node.discovered_at = src_node.discovered_at

        src_status = src_node.properties.get("status", "")
        if src_status == "pwned":
            tgt_node.properties["status"] = "pwned"

        # 3. Rimuovi il nodo sorgente
        del self._nodes[source_host_id]


    # ── Convenience constructors ──────────────────────────────────────────────

    def _rename_subnet_edges(self, old_id: str, new_id: str, old_cidr: str, new_cidr: str) -> None:
        """
        Rinomina e reindirizza gli archi collegati a una subnet allineandoli al nuovo ID.
        """
        old_cidr_str = old_cidr.replace('/', '_')
        new_cidr_str = new_cidr.replace('/', '_')
        
        edges_to_modify = []
        for edge in list(self._edges.values()):
            if edge.from_node == old_id or edge.to_node == old_id:
                edges_to_modify.append(edge)
                
        for edge in edges_to_modify:
            if edge.id in self._edges:
                del self._edges[edge.id]
                
            new_from = new_id if edge.from_node == old_id else edge.from_node
            new_to   = new_id if edge.to_node == old_id else edge.to_node
            
            # Sostituiamo il CIDR vecchio con il nuovo nell'ID dell'arco
            new_edge_id = edge.id.replace(old_cidr_str, new_cidr_str)
            
            new_edge = GraphEdge(
                id=new_edge_id, type=edge.type, from_node=new_from, to_node=new_to,
                source=edge.source, properties=edge.properties
            )
            self._edges[new_edge_id] = new_edge

    def add_subnet(self, cidr: str, *, is_attacker: bool = False,
                   provenance: Provenance | None = None, source: Source = "tool") -> GraphNode:
        import ipaddress
        with self._lock:
            try:
                new_net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                # Fallback if CIDR is malformed
                nid = f"subnet-{cidr.replace('/', '_')}"
                return self.add_node(GraphNode(
                    id=nid, type="Subnet", label=cidr, source=source,
                    provenance=provenance,
                    properties={"cidr": cidr, "is_attacker_network": is_attacker},
                ))

            # Find all existing subnets that overlap with the new one
            overlapping_nodes = []
            for node in list(self._nodes.values()):
                if node.type == "Subnet":
                    existing_cidr = node.properties.get("cidr")
                    if existing_cidr:
                        try:
                            existing_net = ipaddress.ip_network(existing_cidr, strict=False)
                            if new_net.overlaps(existing_net):
                                overlapping_nodes.append((node, existing_net, existing_cidr))
                        except ValueError:
                            continue

            if not overlapping_nodes:
                # No overlap, create new subnet normally
                nid = f"subnet-{cidr.replace('/', '_')}"
                return self.add_node(GraphNode(
                    id=nid, type="Subnet", label=cidr, source=source,
                    provenance=provenance,
                    properties={"cidr": cidr, "is_attacker_network": is_attacker},
                ))

            # If any of the overlapping subnets is wider than or equal to the new one,
            # we just return that existing subnet (preferring the widest one).
            # Widest means smallest prefix length.
            containing_node = None
            for node, ext_net, ext_cidr in overlapping_nodes:
                if ext_net.prefixlen <= new_net.prefixlen:
                    if containing_node is None or ext_net.prefixlen < ipaddress.ip_network(containing_node.properties["cidr"]).prefixlen:
                        containing_node = node
            
            if containing_node:
                # An existing subnet already covers the new one, so return it.
                # If the new one is marked as attacker, propagate this property to the existing one.
                if is_attacker and not containing_node.properties.get("is_attacker_network"):
                    containing_node.properties["is_attacker_network"] = True
                    self._touch()
                    self._save()
                return containing_node

            # Otherwise, the new subnet is wider than all overlapping ones.
            # We must merge all of them into this new, wider subnet.
            new_cidr = str(new_net)
            new_id = f"subnet-{new_cidr.replace('/', '_')}"
            
            # Create the merged subnet node
            merged_node = GraphNode(
                id=new_id, type="Subnet", label=new_cidr, source=source,
                provenance=provenance,
                properties={"cidr": new_cidr, "is_attacker_network": is_attacker},
            )
            
            # If any of the merged subnets was an attacker network, the merged one is too
            for node, _, _ in overlapping_nodes:
                if node.properties.get("is_attacker_network"):
                    merged_node.properties["is_attacker_network"] = True

            # Register the new merged node
            self._nodes[new_id] = merged_node
            
            # Redirect edges from all old subnets to the new merged subnet, and delete them
            for old_node, _, old_cidr in overlapping_nodes:
                if old_node.id != new_id:
                    self._rename_subnet_edges(old_node.id, new_id, old_cidr, new_cidr)
                    if old_node.id in self._nodes:
                        del self._nodes[old_node.id]

            self._touch()
            self._save()
            return merged_node

    def add_host(self, ip: str, *, hostname: str = "", os: str = "",
                 status: str = "up", provenance: Provenance | None = None,
                 source: Source = "tool") -> GraphNode:
        """Register a host by IP. Idempotent: if this IP is already known (as a Host
        or as an Interface on another host), returns or upgrades the existing node
        without creating a duplicate."""
        with self._lock:
            canonical_host_id = self._resolve_canonical_host_id(ip)

            if canonical_host_id in self._nodes:
                existing = self._nodes[canonical_host_id]
                # Merge richer metadata if provided
                if hostname and not existing.properties.get("hostname"):
                    existing.properties["hostname"] = hostname
                if os and not existing.properties.get("os"):
                    existing.properties["os"] = os
                if status == "pwned":
                    existing.properties["status"] = "pwned"
                return existing

            node = GraphNode(
                id=canonical_host_id, type="Host", label=ip, source=source,
                provenance=provenance,
                properties={
                    "ip": ip,
                    "hostname": hostname,
                    "os": os,
                    "status": status,
                    "scout_status": "pending",        # "pending" | "done"
                    "exploit_status": "pending",      # "pending" | "done" | "unsuccessful"
                    "postexploit_status": "pending",  # "pending" | "done"
                },
            )
            return self.add_node(node)

    def set_phase_status(self, ip: str, phase: str, status: str) -> None:
        """Update phase status (scout, exploit, postexploit) for a given host."""
        with self._lock:
            canonical_host_id = self._resolve_canonical_host_id(ip)
            node = self._nodes.get(canonical_host_id)
            if node and node.type == "Host":
                key = f"{phase.lower()}_status"
                node.properties[key] = status.lower()
                if phase.lower() == "exploit" and status.lower() == "done":
                    node.properties["status"] = "pwned"
                self._touch()
                self._save()

    def add_interface(self, host_ip: str, iface_name: str, iface_ip: str, *,
                      mac: str = "", provenance: Provenance | None = None,
                      source: Source = "tool") -> GraphNode:
        with self._lock:
            canonical_host_id = self._resolve_canonical_host_id(host_ip)
            parent_ip = canonical_host_id.replace("host-", "")

            # If an existing Host or Interface node exists for iface_ip, inherit its earliest discovery timestamp
            host_nid = f"host-{iface_ip}"
            earliest_ts = None
            if host_nid in self._nodes and self._nodes[host_nid].discovered_at:
                earliest_ts = self._nodes[host_nid].discovered_at
            else:
                for n in self._nodes.values():
                    if n.type == "Interface" and n.properties.get("ip") == iface_ip and n.discovered_at:
                        if earliest_ts is None or n.discovered_at < earliest_ts:
                            earliest_ts = n.discovered_at

            nid = f"iface-{parent_ip}-{iface_name}"
            node_ts = earliest_ts or (provenance.timestamp if provenance and hasattr(provenance, 'timestamp') and provenance.timestamp else _now())
            node = self.add_node(GraphNode(
                id=nid, type="Interface", label=f"{iface_ip} / {iface_name}",
                source=source, discovered_at=node_ts, provenance=provenance,
                properties={"name": iface_name, "ip": iface_ip, "mac": mac},
            ))

            
            # Auto-link canonical host → interface
            self._safe_add_edge(GraphEdge(
                id=f"e-{parent_ip}-has-{iface_name}", type="HAS_INTERFACE",
                from_node=canonical_host_id, to_node=nid, source=source,
            ))
            
            # Se esiste già un nodo Host temporaneo per questo IP dell'interfaccia (es. host-172.30.0.5),
            # e NON coincide con l'host genitore (host-172.28.0.5), allora facciamo il merge!
            host_nid = f"host-{iface_ip}"
            if host_nid in self._nodes and host_nid != canonical_host_id:
                self._merge_hosts(host_nid, canonical_host_id)
                
            return node

    def add_service(self, host_ip: str, port: int, proto: str = "tcp", *,
                    service_name: str = "", banner: str = "", cves: list[str] | None = None,
                    status: str = "open", web_path: str = "", ssl: bool = False,
                    target_os: str = "", target_arch: str = "",
                    discovered_paths: list[str] | None = None,
                    attributes: dict | None = None,
                    extra_properties: dict | None = None,
                    provenance: Provenance | None = None,
                    source: Source = "tool") -> GraphNode:
        with self._lock:
            canonical_host_id = self._resolve_canonical_host_id(host_ip)
            canonical_ip = canonical_host_id.replace("host-", "")
            nid = f"svc-{canonical_ip}-{port}"

            paths = list(discovered_paths) if discovered_paths else []
            if web_path and web_path not in paths:
                paths.append(web_path)
            eff_web_path = web_path or (paths[0] if paths else "")

            # If node already exists, merge properties incrementally
            if nid in self._nodes:
                existing_node = self._nodes[nid]
                eprops = existing_node.properties
                if service_name:
                    eprops["service_name"] = service_name
                if banner:
                    eprops["banner"] = banner
                if cves:
                    current_cves = set(eprops.get("cves", []))
                    current_cves.update(cves)
                    eprops["cves"] = sorted(list(current_cves))
                if status:
                    eprops["status"] = status
                if eff_web_path:
                    eprops["web_path"] = eff_web_path
                if ssl:
                    eprops["ssl"] = ssl
                if target_os:
                    eprops["target_os"] = target_os
                if target_arch:
                    eprops["target_arch"] = target_arch

                existing_paths = list(eprops.get("discovered_paths", []))
                for p in paths:
                    if p and p not in existing_paths:
                        existing_paths.append(p)
                eprops["discovered_paths"] = existing_paths
                if not eprops.get("web_path") and existing_paths:
                    eprops["web_path"] = existing_paths[0]

                if attributes:
                    eprops.setdefault("attributes", {}).update(attributes)
                if extra_properties:
                    eprops.update(extra_properties)

                if provenance:
                    existing_node.provenance = provenance
                self._touch()
                self._save()
                return existing_node

            props = {
                "port": port, "proto": proto,
                "service_name": service_name,
                "banner": banner, "cves": cves or [], "status": status,
                "web_path": eff_web_path,       # e.g. '/showcase.action', '/wp-login.php'
                "discovered_paths": paths,      # e.g. ['/cgi-bin/vulnerable', '/index.html']
                "attributes": attributes or {}, # e.g. {"server_headers": {...}, "detected_methods": [...]}
                "ssl": ssl,                     # True if HTTPS / SSL TLS
                "target_os": target_os,         # e.g. 'linux', 'windows' (from nmap/banner)
                "target_arch": target_arch,     # e.g. 'x64', 'x86' (from nmap/banner)
            }
            if extra_properties:
                props.update(extra_properties)

            node = self.add_node(GraphNode(
                id=nid, type="Service", label=f"{host_ip}:{port}",
                source=source, provenance=provenance,
                properties=props,
            ))
            # Auto-link host → service
            self._safe_add_edge(GraphEdge(
                id=f"e-{canonical_ip}-runs-{port}", type="RUNS",
                from_node=canonical_host_id, to_node=nid, source=source,
            ))
            return node

    def _resolve_exploit_node_id(self, session_id: int) -> str:
        """
        Dato un session_id, restituisce l'ID canonico del nodo ExploitStep.
        Se la sessione è cambiata (es. da 5 a 6 o 7 a causa di una riconnessione),
        trova il nodo ExploitStep corrispondente mantenendo integri gli archi del grafo.
        """
        direct_id = f"exploit-{session_id}"
        with self._lock:
            if direct_id in self._nodes:
                return direct_id

            # 1. Cerca per property session_id
            for node in self._nodes.values():
                if node.type == "ExploitStep":
                    if str(node.properties.get("session_id")) == str(session_id):
                        return node.id

            # 2. Fallback: ultimo ExploitStep creato per questa campagna
            exploit_nodes = [n for n in self._nodes.values() if n.type == "ExploitStep"]
            if exploit_nodes:
                return exploit_nodes[-1].id

            return direct_id

    def add_exploit_step(self, session_id: int, host_ip: str, port: int,
                         exploit_module: str, payload: str, user: str, *,
                         cve: str = "", lhost: str = "", lport: int = 4444,
                         session_type: str = "meterpreter",
                         extra_properties: dict | None = None,
                         provenance: Provenance | None = None,
                         source: Source = "tool") -> GraphNode:
        with self._lock:
            canonical_host_id = self._resolve_canonical_host_id(host_ip)
            canonical_ip = canonical_host_id.replace("host-", "")
            svc_id = f"svc-{canonical_ip}-{port}"

            # Controlla se esiste già un ExploitStep per questo servizio o host
            existing_exploit_node = None
            for edge in self._edges.values():
                if edge.type == "EXPLOITED_VIA" and edge.from_node == svc_id:
                    existing_exploit_node = self._nodes.get(edge.to_node)
                    break

            new_id = f"exploit-{session_id}"

            base_props = {
                "session_id": session_id,
                "port": port,          # saved explicitly so restore logic can read it
                "exploit_module": exploit_module,
                "payload": payload,
                "user": user,
                "cve": cve,
                "lhost": lhost,
                "lport": lport,
                "session_type": session_type,
            }
            # Internal AKG-only fields that should never be forwarded to MSF as module options.
            # These are metadata tracked in the graph for accounting purposes only.
            _AKG_INTERNAL_KEYS = {
                "session_id", "port", "exploit_module", "payload", "user", "cve",
                "lhost", "lport", "session_type", "target_ip", "target_os", "target_arch",
                "upgraded_from_shell", "upgraded_session_id",
            }
            if extra_properties:
                base_props.update(extra_properties)
                # Also store a clean "extra_options" dict containing only real MSF options.
                # akg_restore_sessions reads this to replay the exact call verbatim.
                msf_opts = {k: v for k, v in extra_properties.items() if k not in _AKG_INTERNAL_KEYS}
                if msf_opts:
                    base_props["extra_options"] = msf_opts

            if existing_exploit_node and existing_exploit_node.id != new_id:
                old_id = existing_exploit_node.id
                print(f"[AKG] Session renewed: updating ExploitStep node and edges from {old_id} to {new_id}")

                # 1. Rimuovi vecchio nodo da self._nodes e reinseriscilo col nuovo ID
                del self._nodes[old_id]
                existing_exploit_node.id = new_id
                existing_exploit_node.label = f"Session {session_id} — {exploit_module.split('/')[-1]}"
                existing_exploit_node.properties.update(base_props)
                self._nodes[new_id] = existing_exploit_node
                node = existing_exploit_node

                # 2. Aggiorna TUTTI gli archi collegati al vecchio ID
                edges_to_modify = list(self._edges.values())
                for edge in edges_to_modify:
                    if edge.from_node == old_id or edge.to_node == old_id:
                        del self._edges[edge.id]
                        new_from = new_id if edge.from_node == old_id else edge.from_node
                        new_to   = new_id if edge.to_node == old_id else edge.to_node
                        
                        # Aggiorna anche eventuale session_id presente nelle properties dell'arco
                        new_props = dict(edge.properties or {})
                        if "session_id" in new_props:
                            new_props["session_id"] = session_id
                        if "via_session_id" in new_props:
                            new_props["via_session_id"] = session_id

                        new_edge_id = edge.id.replace(old_id, new_id)
                        new_edge = GraphEdge(
                            id=new_edge_id, type=edge.type, from_node=new_from, to_node=new_to,
                            source=edge.source, properties=new_props
                        )
                        self._edges[new_edge_id] = new_edge
            elif existing_exploit_node:
                node = existing_exploit_node
                node.properties.update(base_props)
            else:
                node = self.add_node(GraphNode(
                    id=new_id, type="ExploitStep",
                    label=f"Session {session_id} — {exploit_module.split('/')[-1]}",
                    source=source, provenance=provenance,
                    properties=base_props,
                ))

            host_id = canonical_host_id
            exploit_node_id = node.id

            # Service → ExploitStep
            self._safe_add_edge(GraphEdge(
                id=f"e-{svc_id}-exploited-{session_id}", type="EXPLOITED_VIA",
                from_node=svc_id, to_node=exploit_node_id, source=source,
                properties={"cve": cve, "timestamp": _now()},
            ))
            # ExploitStep → Host (COMPROMISES)
            self._safe_add_edge(GraphEdge(
                id=f"e-{exploit_node_id}-compromises-{canonical_ip}", type="COMPROMISES",
                from_node=exploit_node_id, to_node=host_id, source=source,
                properties={"privilege": user, "session_id": session_id},
            ))
            # Mark host as pwned
            if host_id in self._nodes:
                self._nodes[host_id].properties["status"] = "pwned"
            # Mark service as exploited
            if svc_id in self._nodes:
                self._nodes[svc_id].properties["status"] = "exploited"
            self._touch()
            self._save()
            return node

    def add_credential(self, exploit_session_id: int, cred_type: str,
                       label: str, location: str, *,
                       username: str = "", secret: str = "",
                       provenance: Provenance | None = None,
                       source: Source = "tool") -> GraphNode:
        import hashlib
        exploit_node_id = self._resolve_exploit_node_id(exploit_session_id)
        fingerprint = f"{exploit_session_id}:{cred_type}:{username}:{location}"
        short_hash = hashlib.sha1(fingerprint.encode()).hexdigest()[:8]
        nid = f"cred-{exploit_session_id}-{short_hash}"
        node = self.add_node(GraphNode(
            id=nid, type="Credential", label=label, source=source,
            provenance=provenance,
            properties={
                "cred_type": cred_type, "username": username,
                "secret": secret, "location": location,
            },
        ))
        self.add_edge(GraphEdge(
            id=f"e-{exploit_node_id}-yields-{nid}", type="YIELDS",
            from_node=exploit_node_id, to_node=nid, source=source,
        ))
        return node

    def add_pivot(self, exploit_session_id: int, subnet_cidr: str, *,
                  route: str = "", provenance: Provenance | None = None,
                  source: Source = "tool") -> None:
        subnet_nid = self._resolve_subnet_id(subnet_cidr)
        exploit_node_id = self._resolve_exploit_node_id(exploit_session_id)
        self.add_edge(GraphEdge(
            id=f"e-{exploit_node_id}-pivots-{subnet_nid}", type="PIVOTS_INTO",
            from_node=exploit_node_id, to_node=subnet_nid, source=source,
            properties={"via_session_id": exploit_session_id, "route": route},
        ))

    def link_subnet_host(self, subnet_cidr: str, host_ip: str,
                         source: Source = "tool") -> None:
        with self._lock:
            canonical_host_id = self._resolve_canonical_host_id(host_ip)
            parent_ip = canonical_host_id.replace("host-", "")
            subnet_nid = self._resolve_subnet_id(subnet_cidr)
            
            # Check if an Interface node already exists for this exact IP
            matching_iface = None
            for n in self._nodes.values():
                if n.type == "Interface" and n.properties.get("ip") == host_ip:
                    matching_iface = n
                    break

            if matching_iface:
                iface_nid = matching_iface.id
            else:
                # Find an unused interface name (eth0, eth1, etc.) for this host
                existing_iface_names = {
                    n.properties.get("name") for n in self._nodes.values()
                    if n.type == "Interface" and n.id.startswith(f"iface-{parent_ip}-")
                }
                iface_name = "eth0"
                idx = 0
                while iface_name in existing_iface_names:
                    idx += 1
                    iface_name = f"eth{idx}"

                iface_nid = f"iface-{parent_ip}-{iface_name}"
                self.add_node(GraphNode(
                    id=iface_nid, type="Interface", label=f"{host_ip} / {iface_name}",
                    source=source,
                    properties={"name": iface_name, "ip": host_ip, "mac": "unknown"},
                ))
                # Colleghiamo l'host all'interfaccia
                self._safe_add_edge(GraphEdge(
                    id=f"e-{parent_ip}-has-{iface_name}", type="HAS_INTERFACE",
                    from_node=canonical_host_id, to_node=iface_nid, source=source,
                ))

            self._safe_add_edge(GraphEdge(
                id=f"e-{iface_nid}-connects-{subnet_nid}", type="CONNECTS_TO",
                from_node=iface_nid, to_node=subnet_nid, source=source,
            ))

    def link_interface_subnet(self, host_ip: str, iface_name: str,
                               subnet_cidr: str, source: Source = "tool") -> None:
        with self._lock:
            canonical_host_id = self._resolve_canonical_host_id(host_ip)
            parent_ip = canonical_host_id.replace("host-", "")
            iface_nid  = f"iface-{parent_ip}-{iface_name}"
            subnet_nid = self._resolve_subnet_id(subnet_cidr)
            self.add_edge(GraphEdge(
                id=f"e-{iface_nid}-connects-{subnet_nid}", type="CONNECTS_TO",
                from_node=iface_nid, to_node=subnet_nid, source=source,
            ))

    # ── Event log shortcut ────────────────────────────────────────────────────

    def log(self, *, event_type: str, actor: str, source: Source,
            action: str, target: str | None = None,
            reasoning: str | None = None, result: str) -> None:
        seq = len(self._event_log) + 1
        self.log_event(EventLogEntry(
            seq=seq, timestamp=_now(), type=event_type, actor=actor,
            source=source, action=action, target=target,
            reasoning=reasoning, result=result,
        ))

    # ── Queries ───────────────────────────────────────────────────────────────

    def get_hosts(self, status: str | None = None) -> list[GraphNode]:
        with self._lock:
            hosts = [n for n in self._nodes.values() if n.type == "Host"]
            if status:
                hosts = [h for h in hosts if h.properties.get("status") == status]
            return hosts

    def get_active_sessions(self) -> list[GraphNode]:
        with self._lock:
            return [n for n in self._nodes.values() if n.type == "ExploitStep"]

    def get_credentials(self) -> list[GraphNode]:
        with self._lock:
            return [n for n in self._nodes.values() if n.type == "Credential"]

    def get_subnets(self, attacker_only: bool = False,
                    internal_only: bool = False) -> list[GraphNode]:
        with self._lock:
            subnets = [n for n in self._nodes.values() if n.type == "Subnet"]
            pivoted_subnet_ids = {e.to_node for e in self._edges.values() if e.type == "PIVOTS_INTO"}
            if attacker_only:
                subnets = [s for s in subnets if s.properties.get("is_attacker_network") and s.id not in pivoted_subnet_ids]
            if internal_only:
                subnets = [s for s in subnets if (not s.properties.get("is_attacker_network")) or s.id in pivoted_subnet_ids]
            return subnets

    def get_next_targets(self) -> list[str]:
        """Return IPs of hosts that are discovered (up) but not yet pwned/exploited."""
        with self._lock:
            next_targets = []
            for h in self.get_hosts():
                ip = h.properties.get("ip", "")
                if not ip:
                    continue
                canonical_id = self._resolve_canonical_host_id(ip)
                has_exploit_edge = any(
                    edge.type == "COMPROMISES" and edge.to_node == canonical_id
                    for edge in self._edges.values()
                )
                is_exploited = h.properties.get("exploit_status") == "done" or has_exploit_edge
                if not is_exploited:
                    next_targets.append(ip)
            return next_targets

    def summary(self) -> str:
        """Rich text summary for LLM consumption."""
        return self.full_context()

    def _compute_network_topology(self) -> tuple[dict[str, dict], dict[str, dict]]:
        """
        Computes multi-tier network topology, pivot depths, and access paths
        for all discovered subnets and hosts using BFS over verified pivot paths.
        """
        import ipaddress
        from collections import deque

        subnets = [n for n in self._nodes.values() if n.type == "Subnet"]
        hosts = [n for n in self._nodes.values() if n.type == "Host"]
        exploits = [n for n in self._nodes.values() if n.type in ("Exploit", "ExploitStep")]

        pivots = [e for e in self._edges.values() if e.type == "PIVOTS_INTO"]
        compromises = [e for e in self._edges.values() if e.type == "COMPROMISES"]

        exploit_to_host = {e.from_node: e.to_node for e in compromises}

        session_to_host = {}
        for exp in exploits:
            sid = exp.properties.get("session_id")
            hid = exploit_to_host.get(exp.id)
            if sid is not None and hid in self._nodes:
                session_to_host[str(sid)] = self._nodes[hid]

        # Map each host to all known IP addresses (primary IP + Interface IPs)
        host_to_ips = {}
        for h in hosts:
            ips = []
            hip = h.properties.get("ip")
            if hip:
                ips.append(hip)
            canonical_id = self._resolve_canonical_host_id(hip) if hip else h.id
            for e in self._edges.values():
                if e.type == "HAS_INTERFACE" and e.from_node == canonical_id:
                    iface_node = self._nodes.get(e.to_node)
                    if iface_node and iface_node.properties.get("ip"):
                        iface_ip = iface_node.properties.get("ip")
                        if iface_ip not in ips:
                            ips.append(iface_ip)
            host_to_ips[h.id] = ips

        subnet_info = {}
        for s in subnets:
            sid = s.id
            cidr = s.properties.get("cidr", s.label)
            is_att = s.properties.get("is_attacker_network", False)
            subnet_info[sid] = {
                "node": s,
                "cidr": cidr,
                "is_attacker": is_att,
                "depth": None,
                "parent_subnet": None,
                "via_session": None,
                "via_host_ip": None,
                "hosts": [],
            }

        # Extract directed pivot transitions from AKG edges:
        # transition: (parent_subnet_id, target_subnet_id, via_session_id, via_host_ip)
        pivot_transitions = []
        for p in pivots:
            to_sub = p.to_node
            exp_id = p.from_node
            via_sid = str(p.properties.get("via_session_id", ""))
            host_node = session_to_host.get(via_sid)
            if not host_node:
                hid = exploit_to_host.get(exp_id)
                host_node = self._nodes.get(hid)
            if not host_node:
                continue

            candidate_ips = host_to_ips.get(host_node.id, [])
            if not candidate_ips and host_node.properties.get("ip"):
                candidate_ips = [host_node.properties.get("ip")]

            for h_ip in candidate_ips:
                try:
                    h_addr = ipaddress.ip_address(h_ip)
                    for s_id, s_data in subnet_info.items():
                        if s_id != to_sub and s_data["cidr"]:
                            if h_addr in ipaddress.ip_network(s_data["cidr"], strict=False):
                                pivot_transitions.append((s_id, to_sub, via_sid, h_ip))
                except Exception:
                    pass

        # Also inspect live Metasploit session routes to detect active multi-hop pivots
        try:
            from core.rpc_client import msf_client
            raw_s = msf_client.call("session.list")
            if isinstance(raw_s, dict) and "error" not in raw_s:
                for s_id_str, s_info in raw_s.items():
                    routes_str = s_info.get("routes", "")
                    sess_host = s_info.get("session_host")
                    if routes_str and sess_host:
                        for r_entry in str(routes_str).split(","):
                            r_entry = r_entry.strip()
                            if "/" in r_entry:
                                r_sub, r_mask = r_entry.split("/", 1)
                                try:
                                    r_net = ipaddress.ip_network(f"{r_sub}/{r_mask}", strict=False)
                                    matched_sub = None
                                    for sub_id, s_data in subnet_info.items():
                                        if s_data["cidr"]:
                                            c_net = ipaddress.ip_network(s_data["cidr"], strict=False)
                                            if r_net == c_net or r_net.overlaps(c_net):
                                                matched_sub = sub_id
                                                break

                                    if not matched_sub:
                                        matched_sub = f"subnet-{str(r_net).replace('/', '_')}"
                                        subnet_info[matched_sub] = {
                                            "node": None,
                                            "cidr": str(r_net),
                                            "is_attacker": False,
                                            "depth": None,
                                            "parent_subnet": None,
                                            "via_session": None,
                                            "via_host_ip": None,
                                            "hosts": [],
                                        }

                                    h_addr = ipaddress.ip_address(sess_host)
                                    parent_sub = None
                                    for s_id_cand, s_data_cand in subnet_info.items():
                                        c_cand = s_data_cand["cidr"]
                                        if c_cand and h_addr in ipaddress.ip_network(c_cand, strict=False):
                                            if s_id_cand != matched_sub:
                                                parent_sub = s_id_cand
                                                break

                                    if matched_sub and parent_sub:
                                        pivot_transitions.append((parent_sub, matched_sub, s_id_str, sess_host))
                                except Exception:
                                    pass
        except Exception:
            pass

        # Determine root (Tier 0 perimeter) subnets:
        # Subnets that do not require any pivot transition from another subnet.
        incoming_targets = {t[1] for t in pivot_transitions}
        root_subnets = [s_id for s_id in subnet_info if s_id not in incoming_targets]
        if not root_subnets:
            root_subnets = [s_id for s_id, s_data in subnet_info.items() if s_data["is_attacker"]]

        # Breadth-first search (BFS) to compute shortest hop distance (depth) for each subnet
        queue = deque()
        for r_id in root_subnets:
            subnet_info[r_id]["depth"] = 0
            subnet_info[r_id]["is_attacker"] = True
            queue.append(r_id)

        while queue:
            curr_id = queue.popleft()
            curr_depth = subnet_info[curr_id]["depth"]
            for from_sub, to_sub, via_sid, via_ip in pivot_transitions:
                if from_sub == curr_id:
                    new_depth = curr_depth + 1
                    if subnet_info[to_sub]["depth"] is None or new_depth < subnet_info[to_sub]["depth"]:
                        subnet_info[to_sub]["depth"] = new_depth
                        subnet_info[to_sub]["parent_subnet"] = from_sub
                        subnet_info[to_sub]["via_session"] = via_sid
                        subnet_info[to_sub]["via_host_ip"] = via_ip
                        subnet_info[to_sub]["is_attacker"] = False
                        queue.append(to_sub)

        # Any disconnected subnets default to 0 if is_attacker else 1
        for s_id, s_data in subnet_info.items():
            if s_data["depth"] is None:
                s_data["depth"] = 0 if s_data["is_attacker"] else 1

        # Map hosts to subnets and assign depth, tier, route, and role
        host_info = {}
        for h in hosts:
            ip = h.properties.get("ip", "")
            if not ip:
                continue
            try:
                h_addr = ipaddress.ip_address(ip)
            except Exception:
                continue

            assigned_sub = None
            for s_id, s_data in subnet_info.items():
                c = s_data["cidr"]
                try:
                    if c and h_addr in ipaddress.ip_network(c, strict=False):
                        assigned_sub = s_id
                        if ip not in s_data["hosts"]:
                            s_data["hosts"].append(ip)
                        break
                except Exception:
                    pass

            depth = subnet_info[assigned_sub]["depth"] if assigned_sub else 0
            via_session = subnet_info[assigned_sub]["via_session"] if assigned_sub else None
            via_host_ip = subnet_info[assigned_sub]["via_host_ip"] if assigned_sub else None

            # Determine if host has active pivot session
            is_pivot = any(p["via_host_ip"] == ip for p in subnet_info.values() if p["via_host_ip"])
            canonical_host_id = self._resolve_canonical_host_id(ip)
            has_exploit_edge = any(e.type == "COMPROMISES" and e.to_node == canonical_host_id for e in self._edges.values())
            is_pwned = h.properties.get("status") == "pwned" or h.properties.get("exploit_status") == "done" or has_exploit_edge

            if depth == 0:
                tier_str = "Tier 0 (Perimeter Scope)"
                route_str = "Direct (No pivot required)"
            else:
                tier_str = f"Tier {depth} (Internal / {depth} {'Hop' if depth == 1 else 'Hops'})"
                route_str = f"via Session {via_session} on {via_host_ip}" if via_session else "Pivot route required"

            if is_pivot:
                role_str = "Pivot Gateway (Compromised - Routing Active)"
            elif is_pwned:
                role_str = "Compromised Node"
            elif depth == 0:
                role_str = "Perimeter Target (Uncompromised)"
            else:
                role_str = f"Deep Target [Tier {depth}] (Uncompromised)"

            host_info[ip] = {
                "depth": depth,
                "tier": tier_str,
                "route": route_str,
                "role": role_str,
                "is_pivot": is_pivot,
                "is_pwned": is_pwned,
                "subnet": subnet_info.get(assigned_sub, {}).get("cidr", "unknown"),
            }

        return subnet_info, host_info

    def full_context(self) -> str:
        """Rich detailed summary of current Attack Knowledge Graph state for LLM consumption."""
        with self._lock:
            hosts = self.get_hosts()
            pwned = []
            for h in hosts:
                ip_val = h.properties.get("ip", "")
                cid = self._resolve_canonical_host_id(ip_val)
                has_exp = any(
                    e.type == "COMPROMISES" and e.to_node == cid
                    for e in self._edges.values()
                )
                if h.properties.get("exploit_status") == "done" or has_exp:
                    pwned.append(h)

            sessions = self.get_active_sessions()
            creds = self.get_credentials()
            subnets = self.get_subnets(internal_only=True)
            targets = self.get_next_targets()

            subnet_info, host_info = self._compute_network_topology()
            max_depth = max([s["depth"] for s in subnet_info.values()] + [h["depth"] for h in host_info.values()] + [0])
            active_pivots = [e for e in self._edges.values() if e.type == "PIVOTS_INTO"]

            lines = [
                f"=== ATTACK KNOWLEDGE GRAPH CONTEXT [{self.campaign_id}] ===",
                f"Summary: hosts={len(hosts)} (pwned={len(pwned)}) | sessions={len(sessions)} | max_depth={max_depth} hops | active_pivots={len(active_pivots)} | creds={len(creds)} | next_targets={targets}",
                ""
            ]

            # 1. Network Topology & Attack Depth Map
            lines.append("--- NETWORK TOPOLOGY & ATTACK DEPTH MAP ---")
            sorted_subnets = sorted(subnet_info.items(), key=lambda x: x[1]["depth"])
            if not sorted_subnets:
                lines.append("No subnets registered.")
            else:
                for s_id, s_data in sorted_subnets:
                    d = s_data["depth"]
                    cidr = s_data["cidr"]
                    tier_title = f"[Tier {d}: {'Perimeter Scope' if d == 0 else f'Internal Hop {d}'}]"
                    route_note = "Direct (Kali)" if d == 0 else f"ROUTED via Session {s_data['via_session']} on {s_data['via_host_ip']}"
                    lines.append(f"{tier_title} Subnet {cidr} ({route_note})")
                    if not s_data["hosts"]:
                        lines.append("  └─ (No hosts discovered on this subnet yet)")
                    else:
                        for h_ip in sorted(s_data["hosts"]):
                            h_meta = host_info.get(h_ip, {})
                            status_lbl = "PWNED" if h_meta.get("is_pwned") else "UNCOMPROMISED"
                            pivot_lbl = " [PIVOT GATEWAY]" if h_meta.get("is_pivot") else ""
                            lines.append(f"  └─ Host {h_ip} [{status_lbl}]{pivot_lbl} -> {h_meta.get('role')}")
            lines.append("")

            # 2. Host Details & Phase Status (with depth, tier, and routing)
            lines.append("--- TARGET HOSTS & PHASE PROGRESS ---")
            if not hosts:
                lines.append("No hosts registered yet.")
            for h in hosts:
                ip = h.properties.get("ip", "unknown")
                status = h.properties.get("status", "up")
                h_meta = host_info.get(ip, {})
                h_tier = h_meta.get("tier", "Unknown Tier")
                h_route = h_meta.get("route", "Unknown Route")
                h_role = h_meta.get("role", "Node")

                # Phase progress strictly from host node properties
                scout_st = h.properties.get("scout_status", "pending")
                exploit_st = h.properties.get("exploit_status", "pending")
                post_st = h.properties.get("postexploit_status", "pending")

                canonical_host_id = self._resolve_canonical_host_id(ip)
                exploit_node = None
                for edge in self._edges.values():
                    if edge.type == "COMPROMISES" and edge.to_node == canonical_host_id:
                        exploit_node = self._nodes.get(edge.from_node)
                        break

                # Formatting phase status strings
                scout_str = "✓ DONE" if scout_st == "done" else "✗ PENDING"
                if exploit_st == "done":
                    exploit_str = "✓ DONE"
                elif exploit_st == "unsuccessful":
                    exploit_str = "✗ UNSUCCESSFUL"
                else:
                    exploit_str = "✗ PENDING"
                post_str = "✓ DONE" if post_st == "done" else "✗ PENDING"

                lines.append(f"Host {ip} [{status.upper()}] | {h_tier} | Route: {h_route} | Role: {h_role}")
                lines.append(f"  Progress: Scout [{scout_str}] | Exploit [{exploit_str}] | PostExploit [{post_str}]")
                
                services = [n for n in self._nodes.values() if n.type == "Service" and n.id.startswith(f"svc-{ip}-")]
                if not services:
                    lines.append("  Services: none")
                else:
                    lines.append("  Services:")
                    for s in services:
                        sp = s.properties
                        port = sp.get("port")
                        proto = sp.get("proto", "tcp")
                        sname = sp.get("service_name", "")
                        banner = sp.get("banner", "")
                        web_path = sp.get("web_path")
                        ssl_flag = sp.get("ssl", False)
                        cves = sp.get("cves")
                        t_os = sp.get("target_os")
                        t_arch = sp.get("target_arch")

                        discovered_paths = sp.get("discovered_paths", [])
                        attributes = sp.get("attributes", {})

                        svc_parts = [f"Port {port}/{proto}"]
                        if sname:
                            svc_parts.append(f"Service: {sname}")
                        if banner:
                            svc_parts.append(f"Banner: {banner}")
                        if web_path:
                            svc_parts.append(f"WebPath: {web_path}")
                        if discovered_paths:
                            svc_parts.append(f"DiscoveredPaths: {discovered_paths}")
                        if ssl_flag:
                            svc_parts.append("SSL: True")
                        if cves:
                            svc_parts.append(f"CVEs: {cves if isinstance(cves, str) else ', '.join(cves)}")
                        if t_os or t_arch:
                            svc_parts.append(f"OS/Arch: {t_os or 'unknown'}/{t_arch or 'unknown'}")
                        if attributes:
                            svc_parts.append(f"Attributes: {attributes}")
                        
                        std_svc_keys = {"port", "proto", "service_name", "banner", "web_path", "discovered_paths", "attributes", "ssl", "cves", "target_os", "target_arch", "status"}
                        extra_svc = {k: v for k, v in sp.items() if k not in std_svc_keys}
                        if extra_svc:
                            svc_parts.append(f"Extra: {extra_svc}")

                        lines.append(f"    - {' | '.join(svc_parts)}")

                if exploit_node:
                    props = exploit_node.properties
                    sid = props.get("session_id")
                    mod = props.get("exploit_module")
                    pay = props.get("payload")
                    usr = props.get("user")
                    
                    rport = props.get("port")
                    if rport is None:
                        prov = getattr(exploit_node, "provenance", None)
                        if prov and isinstance(prov, dict):
                            rport = prov.get("args", {}).get("rport")
                        elif hasattr(exploit_node, "provenance") and hasattr(exploit_node.provenance, "args"):
                            rport = (exploit_node.provenance.args or {}).get("rport")
                    if rport is None:
                        rport = 80

                    stype = props.get("session_type", "meterpreter")
                    
                    std_keys = {"session_id", "exploit_module", "payload", "user", "cve", "lhost", "lport", "session_type", "port"}
                    extra_opts = {k: v for k, v in props.items() if k not in std_keys}
                    extra_str = f" | ExtraOpts: {extra_opts}" if extra_opts else ""
                    lines.append(f"  Session:  Session {sid} ({stype}, {usr}) via {mod} (Port: {rport}) [Payload: {pay}]{extra_str}")
                else:
                    lines.append("  Session:  no active session")

            lines.append("")
            lines.append("--- ESTABLISHED PIVOTS ---")
            pivots = [e for e in self._edges.values() if e.type == "PIVOTS_INTO"]
            if not pivots:
                lines.append("No active pivot routes.")
            for p in pivots:
                via_sid = p.properties.get("via_session_id")
                subnet_id = p.to_node.replace("subnet-", "")
                lines.append(f"  Session {via_sid} ---> Subnet {subnet_id} (route: {p.properties.get('route', '')})")

            lines.append("")
            lines.append("--- RECOMMENDED NEXT TARGETS ---")
            if not targets:
                lines.append("No uncompromised targets pending. Attack chain complete.")
            else:
                for target_ip in targets:
                    t_meta = host_info.get(target_ip, {})
                    lines.append(f"  -> Host {target_ip} | Depth: {t_meta.get('tier', 'Unknown')} | Route: {t_meta.get('route', 'Direct')} | Role: {t_meta.get('role', 'Target')}")

            lines.append("")
            lines.append("--- HARVESTED CREDENTIALS ---")
            if not creds:
                lines.append("No credentials harvested.")
            for c in creds:
                cp = c.properties
                lines.append(f"  [{cp.get('cred_type')}] user={cp.get('username')} secret={cp.get('secret')} @ {cp.get('location')}")

            lines.append("==================================================")
            return "\n".join(lines)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _touch(self) -> None:
        self._updated_at = _now()

    def _save(self) -> None:
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "campaign_id": self.campaign_id,
                "created_at":  self._created_at,
                "updated_at":  self._updated_at,
                "meta": {
                    "formalism":   self.FORMALISM,
                    "generation":  self.GENERATION,
                    "references":  self.REFERENCES,
                },
                "nodes":     [n.to_dict() for n in self._nodes.values()],
                "edges":     [e.to_dict() for e in self._edges.values()],
                "event_log": [ev.to_dict() for ev in self._event_log],
            }
            # Atomic write: ensure directory exists, write to tmp then rename
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".json.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(tmp, self._path)


    def save(self) -> None:
        """Force save (useful after bulk operations)."""
        with self._lock:
            self._save()

    @classmethod
    def load(cls, campaign_id: str, campaign_dir: str = "campaigns") -> "AttackGraph":
        """Load an existing graph from disk, or return a fresh empty graph."""
        g = cls(campaign_id, campaign_dir)
        path = g._path
        if not path.exists():
            return g
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            g._created_at = data.get("created_at", _now())
            g._updated_at = data.get("updated_at", _now())
            for nd in data.get("nodes", []):
                prov = nd.get("provenance")
                node = GraphNode(
                    id=nd["id"], type=nd["type"], label=nd["label"],
                    source=nd.get("source", "tool"),
                    discovered_at=nd.get("discovered_at", _now()),
                    provenance=Provenance(
                        tool=prov["tool"], args=prov.get("args", {}),
                        raw_output=prov.get("raw_output", ""),
                        timestamp=prov.get("timestamp", _now()),
                    ) if prov else None,
                    properties=nd.get("properties", {}),
                )
                g._nodes[node.id] = node
                # Rebuild IP index: Host nodes take priority over Interface nodes
                if node.type == "Host":
                    ip = node.properties.get("ip", "")
                    if ip:
                        g._ip_index[ip] = node.id
                elif node.type == "Interface":
                    iface_ip = node.properties.get("ip", "")
                    if iface_ip and iface_ip not in g._ip_index:
                        g._ip_index[iface_ip] = node.id
            for ed in data.get("edges", []):
                edge = GraphEdge(
                    id=ed["id"], type=ed["type"],
                    from_node=ed["from"], to_node=ed["to"],
                    source=ed.get("source", "tool"),
                    properties=ed.get("properties", {}),
                )
                g._edges[edge.id] = edge
            for ev in data.get("event_log", []):
                g._event_log.append(EventLogEntry(
                    seq=ev["seq"], timestamp=ev["timestamp"],
                    type=ev["type"], actor=ev["actor"],
                    source=ev.get("source", "tool"),
                    action=ev["action"], target=ev.get("target"),
                    reasoning=ev.get("reasoning"), result=ev["result"],
                ))
        except (json.JSONDecodeError, KeyError) as e:
            # Corrupt file: start fresh (don't crash the framework)
            print(f"[AKG] Warning: could not load {path}: {e}. Starting fresh.")
        return g

    load_or_create = load


# ── Module-level singleton ────────────────────────────────────────────────────
# The Orchestrator accesses a single shared graph instance per process.
# Initialized lazily via init_graph().

_active_graph: AttackGraph | None = None
_active_graph_campaign_id: str | None = None   # tracks which campaign is loaded
ACTIVE_CAMPAIGN_FILE = Path("campaigns") / ".active_campaign"


def set_active_campaign_id(campaign_id: str):
    try:
        ACTIVE_CAMPAIGN_FILE.parent.mkdir(parents=True, exist_ok=True)
        ACTIVE_CAMPAIGN_FILE.write_text(campaign_id.strip(), encoding="utf-8")
    except Exception:
        pass


def get_active_campaign_id(default: str = "drupal-lab") -> str:
    try:
        if ACTIVE_CAMPAIGN_FILE.exists():
            cid = ACTIVE_CAMPAIGN_FILE.read_text(encoding="utf-8").strip()
            if cid:
                return cid
    except Exception:
        pass
    return default


def init_graph(campaign_id: str, campaign_dir: str = "campaigns") -> AttackGraph:
    """Initialize (or reload) the global graph. Call once at campaign start."""
    global _active_graph, _active_graph_campaign_id
    set_active_campaign_id(campaign_id)
    _active_graph = AttackGraph.load(campaign_id, campaign_dir)
    _active_graph_campaign_id = campaign_id
    _active_graph.save()  # Ensure graph.json exists on disk immediately for dashboard discovery
    print(f"[AKG] Loaded: {_active_graph.summary()}")
    return _active_graph


def get_graph() -> AttackGraph:
    """Return the active graph.

    Always checks .active_campaign on disk. If the campaign changed since the last
    call (e.g. akg_set_campaign was called, or the process restarted), the graph is
    reloaded from disk automatically.  Within the same campaign the in-memory
    singleton is reused to avoid redundant I/O.
    """
    global _active_graph, _active_graph_campaign_id
    cid_on_disk = get_active_campaign_id("drupal-lab")
    if _active_graph is None or _active_graph_campaign_id != cid_on_disk:
        _active_graph = AttackGraph.load(cid_on_disk, "campaigns")
        _active_graph_campaign_id = cid_on_disk
        print(f"[AKG] Loaded active campaign '{cid_on_disk}': {_active_graph.summary()}")
    return _active_graph



# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

