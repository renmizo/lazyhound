"""Build a VisualGraph for each diagram kind from analysis output."""
from __future__ import annotations

from lazyhound.finder.collect.analyzer import Category, get_edge_weight
from lazyhound.finder.tier_zero import is_tier_zero_object

from .model import VisualGraph, VisualNode, VisualEdge, node_type_for, sanitize_id

KINDS = ("paths", "blast", "trusts", "delegation", "graph")


def _index(data: dict):
    objs = data.get("objects", [])
    cls = {o.get("object_sid"): o.get("object_class", "") for o in objs if o.get("object_sid")}
    by_sid = {o.get("object_sid"): o for o in objs if o.get("object_sid")}
    return cls, by_sid


def _ensure_node(g, sid, label, cls_by_sid, by_sid, owned):
    nid = sanitize_id(sid)
    if nid not in g.nodes:
        obj = by_sid.get(sid, {"object_sid": sid, "object_class": cls_by_sid.get(sid, ""),
                               "properties": {}})
        g.nodes[nid] = VisualNode(
            id=nid, label=label or sid, ntype=node_type_for(cls_by_sid.get(sid, "")),
            tier_zero=is_tier_zero_object(obj), owned=(sid in owned),
        )
    return g.nodes[nid]


def _target_node_for_finding(g, f, data_idx, cls_by_sid, by_sid, owned):
    """Resolve (or synthesize) the target node for a single-edge finding.

    Prefers the real collection object (by SID in details, then DN, then name)
    so Tier-Zero status / type are accurate; otherwise synthesizes a node from
    the finding's target_name + target_class."""
    by_dn, by_name = data_idx
    tsid = f.details.get("target_sid")
    obj = None
    if tsid and tsid in by_sid:
        obj = by_sid[tsid]
    elif f.target_dn and f.target_dn in by_dn:
        obj = by_dn[f.target_dn]
    elif f.target_name and f.target_name.lower() in by_name:
        obj = by_name[f.target_name.lower()]
    if obj is not None:
        return _ensure_node(g, obj.get("object_sid"),
                            obj.get("name") or obj.get("dn") or f.target_name,
                            cls_by_sid, by_sid, owned)
    # synthesize
    key = f.target_dn or f.target_name or f"{f.category.value}-target"
    nid = sanitize_id(key)
    if nid not in g.nodes:
        fake = {"object_sid": key, "object_class": f.target_class or "",
                "properties": {}}
        g.nodes[nid] = VisualNode(
            id=nid, label=f.target_name or key,
            ntype=node_type_for(f.target_class or ""),
            tier_zero=is_tier_zero_object(fake), owned=False)
    return g.nodes[nid]


def build_findings_graph(findings, data, owned=None, title="Findings",
                         subtitle="", max_items=60) -> VisualGraph:
    """Render an arbitrary set of findings as a graph.

    Multi-hop findings (with path_sids) are drawn as full paths; single-edge
    findings (LAPS read, ACL abuse, ownership, gMSA/LAPS, sessions, …) become a
    single principal -[right]-> target edge. Lets the operator export a diagram
    of ANY finding category, not just Tier-Zero paths."""
    cls_by_sid, by_sid = _index(data)
    objs = data.get("objects", [])
    by_dn = {o.get("dn"): o for o in objs if o.get("dn")}
    by_name = {o.get("name", "").lower(): o for o in objs if o.get("name")}
    owned = set(owned or set())
    g = VisualGraph(kind="findings", title=title, subtitle=subtitle)

    fs = list(findings)[:max_items]
    path_fs = [f for f in fs if f.details.get("path_sids")]
    edge_fs = [f for f in fs if not f.details.get("path_sids")]
    _add_paths(g, path_fs, cls_by_sid, by_sid, owned)

    seen = set()
    for f in edge_fs:
        psid = f.principal_sid
        if not psid:
            continue
        pnode = _ensure_node(g, psid, f.principal_name or psid,
                             cls_by_sid, by_sid, owned)
        tnode = _target_node_for_finding(g, f, (by_dn, by_name),
                                         cls_by_sid, by_sid, owned)
        # Property-style findings (kerberoast, AS-REP, dangerous config) describe
        # the principal itself — target resolves to the same node. Highlight the
        # affected object instead of drawing a meaningless self-loop.
        if tnode.id == pnode.id:
            pnode.is_target = True
            continue
        tnode.is_target = True
        label = (f.rights[0] if f.rights else f.category.value)
        key = (sanitize_id(psid), tnode.id, label)
        if key in seen:
            continue
        seen.add(key)
        g.edges.append(VisualEdge(src=sanitize_id(psid), dst=tnode.id,
                                  label=label, weight=get_edge_weight(label)))
    return g


def _path_findings(result, category, max_paths):
    fs = [f for f in result.findings if f.category == category]
    fs.sort(key=lambda f: f.details.get("depth", 99))
    return fs[:max_paths]


def _add_paths(g, findings, cls_by_sid, by_sid, owned):
    seen_edges = set()
    for f in findings:
        sids = f.details.get("path_sids", [])
        names = f.details.get("path_names", [])
        edges = f.details.get("path_edges", [])
        for i, sid in enumerate(sids):
            _ensure_node(g, sid, names[i] if i < len(names) else sid,
                         cls_by_sid, by_sid, owned)
        if sids:
            g.nodes[sanitize_id(sids[-1])].is_target = True
        for i, label in enumerate(edges):
            if i + 1 >= len(sids):
                break
            key = (sanitize_id(sids[i]), sanitize_id(sids[i + 1]), label)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            g.edges.append(VisualEdge(src=key[0], dst=key[1], label=label,
                                      weight=get_edge_weight(label)))


def build_visual_graph(kind: str, result, data: dict, max_paths: int = 25) -> VisualGraph:
    if kind not in KINDS:
        raise ValueError(f"Unknown diagram kind: {kind!r} (choose from {', '.join(KINDS)})")
    cls_by_sid, by_sid = _index(data)
    owned = set(getattr(result, "owned_sids", set()) or set())
    domain = getattr(result, "domain", "") or data.get("meta", {}).get("domain", "")

    if kind == "paths":
        g = VisualGraph(kind="paths",
                        title=f"Attack Paths to Tier Zero — {domain}",
                        subtitle="Shortest privilege-escalation paths to "
                                 "high-value targets")
        _add_paths(g, _path_findings(result, Category.SHORTEST_PATH, max_paths),
                   cls_by_sid, by_sid, owned)
        return g

    if kind == "blast":
        g = VisualGraph(kind="blast", title=f"Blast Radius — {domain}")
        bf = [f for f in result.findings if f.category == Category.BLAST_RADIUS
              and f.details.get("path_sids")]
        bf.sort(key=lambda f: f.details.get("depth", 99))
        _add_paths(g, bf[:max_paths], cls_by_sid, by_sid, owned)
        return g

    if kind == "trusts":
        g = VisualGraph(kind="trusts", title=f"Domain Trusts — {domain}")
        dom_obj = next((o for o in data.get("objects", [])
                        if (o.get("object_class") or "").lower() == "domain"), None)
        local_sid = (dom_obj or {}).get("object_sid", "local")
        local_name = (dom_obj or {}).get("name", domain or "local")
        _ensure_node(g, local_sid, local_name, cls_by_sid, by_sid, owned)
        for o in data.get("objects", []):
            if (o.get("object_class") or "").lower() != "trusteddomain":
                continue
            props = o.get("properties", {})
            tsid = props.get("securityIdentifier") or o.get("object_sid") or o.get("name")
            tname = o.get("name", tsid)
            _ensure_node(g, tsid, tname, cls_by_sid, by_sid, owned)
            try:
                direction = int(props.get("trustDirection") or 0)
            except (ValueError, TypeError):
                direction = 0
            if direction in (2, 3):
                g.edges.append(VisualEdge(sanitize_id(local_sid), sanitize_id(tsid), "trusts"))
            if direction in (1, 3):
                g.edges.append(VisualEdge(sanitize_id(tsid), sanitize_id(local_sid), "trusts"))
        return g

    if kind == "delegation":
        g = VisualGraph(kind="delegation", title=f"Delegation — {domain}")
        spn_to_sid: dict[str, str] = {}
        for o in data.get("objects", []):
            sid = o.get("object_sid") or ""
            for spn in (o.get("properties", {}).get("servicePrincipalName") or []):
                host = spn.split("/", 1)[-1].split(":")[0].lower() if "/" in spn else ""
                if host:
                    spn_to_sid[host] = sid
                spn_to_sid[spn.lower()] = sid
        for o in data.get("objects", []):
            sid = o.get("object_sid") or ""
            if not sid:
                continue
            targets = o.get("properties", {}).get("msDS-AllowedToDelegateTo") or []
            if isinstance(targets, str):
                targets = [targets]
            if not targets:
                continue
            _ensure_node(g, sid, o.get("name", sid), cls_by_sid, by_sid, owned)
            for spn in targets:
                host = spn.split("/", 1)[-1].split(":")[0].lower() if "/" in spn else ""
                tsid = spn_to_sid.get(spn.lower()) or spn_to_sid.get(host)
                if not tsid or tsid == sid:
                    continue
                _ensure_node(g, tsid, by_sid.get(tsid, {}).get("name", tsid),
                             cls_by_sid, by_sid, owned)
                g.edges.append(VisualEdge(sanitize_id(sid), sanitize_id(tsid), "AllowedToDelegate"))
        return g

    if kind == "graph":
        from lazyhound.finder.collect.analyzer import _build_attack_graph
        g = VisualGraph(kind="graph", title=f"Attack Graph — {domain}")
        fwd, sid_names, _ = _build_attack_graph(data.get("objects", []),
                                                sid_map=data.get("sid_map", {}))
        for src, edges in fwd.items():
            _ensure_node(g, src, sid_names.get(src, src), cls_by_sid, by_sid, owned)
            for dst, label in edges:
                _ensure_node(g, dst, sid_names.get(dst, dst), cls_by_sid, by_sid, owned)
                g.edges.append(VisualEdge(sanitize_id(src), sanitize_id(dst), label,
                                          weight=get_edge_weight(label)))
        return g

    raise NotImplementedError(kind)  # unreachable: kind already validated
