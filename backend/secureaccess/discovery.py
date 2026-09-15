from dataclasses import asdict, dataclass
from urllib.parse import parse_qs, urlsplit

from lxml import etree

MONITORING = "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"
LIBRARY = "urn:ietf:params:xml:ns:yang:ietf-yang-library"
NATIVE = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"


def parse_xml(xml):
    return etree.fromstring(xml.encode() if isinstance(xml, str) else xml,
                            etree.XMLParser(resolve_entities=False, no_network=True))


@dataclass(frozen=True)
class Model:
    name: str
    revision: str = ""
    namespace: str = ""
    source: str = "hello"


@dataclass
class Inventory:
    capabilities: list[str]
    models: list[Model]
    warnings: list[str]

    def supports(self, feature: str) -> bool:
        prefix = f"urn:ietf:params:netconf:capability:{feature}:"
        return any(c.split("?", 1)[0].startswith(prefix) for c in self.capabilities)

    def as_dict(self):
        return asdict(self)


def discover(session) -> Inventory:
    caps = sorted(str(c) for c in session.server_capabilities)
    models = set()
    warnings = []
    for cap in caps:
        query = parse_qs(urlsplit(cap).query)
        if "module" in query:
            models.add(Model(query["module"][0], query.get("revision", [""])[0],
                             cap.split("?", 1)[0]))
    filters = []
    if any("ietf-netconf-monitoring" in c for c in caps):
        filters.append((MONITORING, "netconf-state", "schemas"))
    if any("yang-library" in c for c in caps):
        filters.extend([(LIBRARY, "yang-library", None), (LIBRARY, "modules-state", None)])
    for namespace, root_name, child in filters:
        root = etree.Element(f"{{{namespace}}}{root_name}")
        if child:
            etree.SubElement(root, f"{{{namespace}}}{child}")
        try:
            reply = session.get(filter=("subtree", etree.tostring(root).decode()))
            tree = parse_xml(reply.data_xml)
            for node in tree.iter():
                qname = etree.QName(node)
                if qname.namespace != namespace or qname.localname not in ("schema", "module", "import-only-module"):
                    continue
                fields = {etree.QName(c).localname: c.text or "" for c in node}
                name = fields.get("identifier") or fields.get("name")
                if name:
                    models.add(Model(name, fields.get("revision") or fields.get("version", ""),
                                     fields.get("namespace", ""), root_name))
        except Exception:
            # RPC exception text can contain device data. Never expose it in reports.
            warnings.append(f"Could not read {root_name}; model inventory may be incomplete")
    return Inventory(caps, sorted(models, key=lambda m: (m.name, m.revision, m.source)), warnings)


def read_native(session) -> str:
    """Read current native configuration into memory; never persist raw crypto data."""
    return session.get_config(source="running", filter=("subtree", f'<native xmlns="{NATIVE}"/>')).data_xml
