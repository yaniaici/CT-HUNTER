"""Infrastructure correlation graph.

Two domains that share an attribute (IP, ASN, registrar, nameserver) get
linked through a shared "attribute" node for that value. This is a
standard bipartite entity-resolution pattern: domains are one node type,
shared attributes are the other, and an edge only ever connects a domain
to an attribute, never domain to domain directly. Two domains end up in
the same connected component exactly when they share at least one
attribute, chained through however many attributes and domains it takes,
which is the actual infrastructure-reuse finding a simple ASN-only text
match (see reputation.asn_reuse) cannot express: it only catches domains
sharing the SAME single attribute, not domains connected through a chain
of different shared attributes.

Deliberately not going through a full graph database (Neo4j, etc.) for a
few hundred rows; networkx in memory, rebuilt on demand from the SQLite
table, is enough and stays easy to reason about.
"""

from __future__ import annotations

import sqlite3

import networkx as nx
from pyvis.network import Network

STATUS_COLORS = {
    "confirmado_malicioso": "#e74c3c",
    "en_seguimiento": "#f39c12",
    "nuevo": "#3498db",
    "descartado": "#7f8c8d",
}
ATTRIBUTE_COLOR = "#95a5a6"

# column -> (node label prefix, human-readable kind)
ATTRIBUTE_COLUMNS = {
    "ip_address": ("IP", "IP address"),
    "asn": ("ASN", "ASN"),
    "registrar": ("Registrar", "registrar"),
}

# ASNs known to run large-scale, multi-tenant domain parking or similar
# shared services, not attacker-specific infrastructure. Correlating on
# these produces misleading mega-clusters of unrelated domains: confirmed
# with real data where ~76 unrelated fuzzy-match hits all shared Sedo's
# parking IPs, which looked like one coordinated campaign but was really
# dozens of unrelated parked domains sitting on the same commercial
# parking service. Excluded from the graph entirely rather than just
# scored down, since as an attribute they carry no correlation signal.
KNOWN_SHARED_INFRASTRUCTURE_ASNS = {
    "AS47846 SEDO GmbH",           # domain parking
    "AS206834 Team Internet AG",   # domain parking (ParkingCrew)
    "AS16509 Amazon.com, Inc.",    # AWS: large multi-tenant cloud, generic hosting
    "AS40034 Confluence Networks Inc",  # observed hosting dozens of unrelated domains in this data
}


def _parse_nameservers(raw: str | None) -> list[str]:
    return [ns for ns in (raw or "").split(",") if ns]


def build_graph(rows: list[sqlite3.Row]) -> nx.Graph:
    # First pass: an IP counts as "known shared infrastructure" if ANY row
    # in this batch has it paired with a known parking/shared-hosting ASN.
    # Needed because not every row has its own asn column populated yet
    # (enrich-reputation has to have run on it), but it can still share the
    # exact same IP as a row that does have that ASN on record.
    shared_ips = {
        row["ip_address"]
        for row in rows
        if "asn" in row.keys() and row["asn"] in KNOWN_SHARED_INFRASTRUCTURE_ASNS and row["ip_address"]
    }

    g = nx.Graph()

    for row in rows:
        domain = row["domain"]
        g.add_node(
            domain,
            kind="domain",
            brand=row["brand"],
            status=row["status"],
            score=row["score"],
            technique=row["technique"],
        )

        row_asn = row["asn"] if "asn" in row.keys() else None
        is_shared_infrastructure = row_asn in KNOWN_SHARED_INFRASTRUCTURE_ASNS

        for column, (prefix, _) in ATTRIBUTE_COLUMNS.items():
            value = row[column] if column in row.keys() else None
            if not value:
                continue
            # IP and ASN both come from a known parking/shared-hosting
            # provider: neither carries correlation signal for this row,
            # since dozens of unrelated domains sit behind the same
            # handful of IPs and the same ASN.
            if column == "asn" and is_shared_infrastructure:
                continue
            if column == "ip_address" and value in shared_ips:
                continue
            attr_node = f"{prefix}: {value}"
            if attr_node not in g:
                g.add_node(attr_node, kind="attribute", attribute_type=prefix)
            g.add_edge(domain, attr_node)

        for ns in _parse_nameservers(row["nameservers"] if "nameservers" in row.keys() else None):
            attr_node = f"NS: {ns}"
            if attr_node not in g:
                g.add_node(attr_node, kind="attribute", attribute_type="NS")
            g.add_edge(domain, attr_node)

    return g


def cluster_for_domain(g: nx.Graph, domain: str) -> set[str] | None:
    """Other domains sharing infrastructure with `domain` (its full
    connected component, minus itself), or None if it is isolated or not
    in the graph at all."""
    if domain not in g:
        return None
    component = nx.node_connected_component(g, domain)
    others = {n for n in component if n != domain and g.nodes[n].get("kind") == "domain"}
    return others or None


def shared_attributes_for_domain(g: nx.Graph, domain: str) -> list[str]:
    """Attribute nodes (IP/ASN/registrar/nameserver) directly attached to
    `domain` in the graph, i.e. what it is actually correlated on."""
    if domain not in g:
        return []
    return sorted(n for n in g.neighbors(domain) if g.nodes[n].get("kind") == "attribute")


def connected_clusters(g: nx.Graph) -> list[set[str]]:
    """Groups of 2+ domains that end up connected through shared
    infrastructure, the actual reuse finding. Domains with no shared
    attribute at all never appear here (each sits in its own
    single-domain component)."""
    domain_nodes = {n for n, data in g.nodes(data=True) if data.get("kind") == "domain"}
    clusters = []
    for component in nx.connected_components(g):
        domains_in_component = component & domain_nodes
        if len(domains_in_component) >= 2:
            clusters.append(domains_in_component)
    return clusters


def render_html(g: nx.Graph) -> str:
    net = Network(height="650px", width="100%", bgcolor="#1e1e1e", font_color="#eeeeee")
    net.barnes_hut(spring_length=120)

    for node, data in g.nodes(data=True):
        if data.get("kind") == "domain":
            color = STATUS_COLORS.get(data.get("status"), STATUS_COLORS["nuevo"])
            title = f"{data.get('brand')} | {data.get('technique')} | score {data.get('score')}"
            net.add_node(node, label=node, color=color, title=title, shape="dot", size=18)
        else:
            net.add_node(node, label=node, color=ATTRIBUTE_COLOR, title=data.get("attribute_type", ""), shape="box")

    for a, b in g.edges():
        net.add_edge(a, b, color="#555555")

    return net.generate_html(notebook=False)
