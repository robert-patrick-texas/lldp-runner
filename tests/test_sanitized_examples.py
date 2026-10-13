"""Repository guard against reintroducing operation-derived identifiers."""

from __future__ import annotations

import ipaddress
import re
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRECTORY_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
}

# Digests let the regression recognize previously removed values without
# retaining those customer-derived values as readable source text.
FORBIDDEN_COMPONENT_DIGESTS = {
    "d930bfe458205857fe8d98255abbbfdb4654c577956fc05082f71abc657d9502": "legacy endpoint DNS label",
    "3a8622e29451e59bf85566250ed72217ee5a5ba3915f2dc4f0ef4eab9a1f3e96": "legacy compound host 1",
    "f71ebd37e97189b501040505966707949a0a5c5971dff1ff95ed0dd6557d7050": "legacy compound host 2",
    "3d1667ebb29f863c3f9102ca3b747373cff5bf05f07642b2f0423c3e684fb3f5": "legacy site host 1",
    "b62b828615cb1fada05ea62ff726338cdbb06e19892a1ad17a4b596a5c713bb7": "legacy site host 2",
    "16e51a7e743b52410073ac2e84e7818e48315ba20cd863950815a3cea584f518": "legacy transit host",
    "cb4c39ebbd80a6496c44b6dff4c0e5322d4b11fefeb95e62f6b70997aad26ba3": "legacy access host",
    "b3fb2dbfa85790d80a966c4078ce42704074ea5112966774abb7dc0dc0eabf3c": "legacy router host",
    "cea520f9c9eb0ad575a39e2a9a0fb2c2d86c29269eadfd4a51ed21c9b053b550": "legacy virtual host 1",
    "333e4de96dee16c60a0bf08c8b30fe7c94793585bed0d441381dd3963f750ced": "legacy virtual host 2",
    "b8d49ed1a286cccb398a15751689710b3050706dfed0959a62f1dc5a2ac79f33": "legacy asset 1",
    "7dedbe86c3b96a89f97e63f8413ea6f877800bca17f9b6139be6aa956420c1a1": "legacy asset 2",
    "335c1acced66fe337a070834558dd90b43b63be7e4139a2fb92fae72c48f3182": "legacy asset 3",
    "8e2c9e7f7a50ee21ed723866780011b3aa6313ffacf85a3071ce900a9f04f017": "legacy asset 4",
    "158a140a246711fe0000681aa79609441ff41a62cc9e69054099fa8544a5f524": "legacy local chassis",
    "e48fc41e5ae93105bdcfc857e33d96d353cd13fec3457f29a5fcb9783f8ece06": "legacy serial 1",
    "d29637d36af3157303847e11aa7ff95c381f5c7034f9da7737f75a5bc788cfcd": "legacy serial 2",
    "b83c39918f7f45fbe70c78edefe5a27cf765982372d9786454ea54c9885ee799": "legacy serial 3",
    "31481f898d45f0148ca684c79fc47f81d175f69ff074958b807e06bf498ad1a7": "legacy credential username 1",
    "f23a41beb935c8b141b5c37a954cba87eadfaae8dfa548b91b9b4e0468e16912": "legacy credential username 2",
    "5212a7fdd1c814d4dc48aea3661468c2de1f322ab9567004c5ef2a5d58864593": "legacy endpoint label",
    "e434e3463e58bc8f39157b367b06998507b4567fe9f276c171a5914e494d3f2b": "legacy packed ipv6",
}
FORBIDDEN_PREFIX_DIGESTS = {
    (4, "e6a9234d05826fe6f2ea72379cd1f4044ae72c2c0f62385b714fe46db03e6bd1"): "legacy site prefix 1",
    (4, "783d8cea961d1e3e3bcc2d64de9a17b685496a1387345becde3f0e3b5c61facf"): "legacy site prefix 2",
    (4, "3f38d3c3a454ae6fcb9846199a2d4b7beb3177d567fa2a87dfed9e4828b258f3"): "legacy site prefix 3",
    (5, "3877b704f2862b0c72f334f8bb67fe83df4ff628a50d7464a1ae66f0d6028c17"): "legacy site prefix 4",
    (5, "579a2924b9c9ae37c85bb2b919b4fcaefbd546c9b34ea161c92ebb94135df51f"): "legacy site prefix 5",
    (5, "8ef12b3d3a452a08c7459875b00f266317de1ecec98be22f1403d61563b39ed9"): "legacy site prefix 6",
}
FORBIDDEN_DOMAIN_SUFFIX_DIGESTS = {
    "4ee93ee2ca4f6e3b0f84b6307710fec185a566051abbf6318bb167b5b9038747": "legacy organization domain 1",
    "1a03096771a4496b5440687fbe9cf5f7b703e82d40afce1590d772705519dc94": "legacy organization domain 2",
    "596e8acc51a32d12fcbf20d6372b2407c0e662513bb3195046fce4356f8772e2": "legacy organization domain 3",
    "e237f30a30a5eee8f7190f83fa2431ee028634f594edd4f2733f9232e34985ec": "legacy organization domain 4",
    "050497fd5d38d6e28fb53e23402562e157a40d4f91b524c8ec493ebf87477f43": "legacy organization domain 5",
    "5caad237a54e098c0edad957ce94fc7c14bf4b7af3e99388b4944e4aa77222a4": "legacy organization domain 6",
    "69b5e0fec2c3448323966e4c38267fd64187da7809af6f7459f4d3833b0bbadd": "legacy organization domain 7",
    "50d3a7dabaf5764e47920d459a143afee6fe7bd258e42ab2d8ecbb4bf20e94aa": "legacy organization domain 8",
}
FORBIDDEN_IP_DIGESTS = {
    "9bd78e139bd19523bef3d8c8b81dc5f41b12d6e766bad9e5fe362976b7a2fce1": "legacy link-local example",
    "0bdd4e548a2ee1d07da01471570c1d28599f143f79858faf5db8218e8d8dfd87": "legacy private documentation network",
    "cc2a365fbc570b4e5e8ed17c61b51c63bd11e35bda416e33dbc36ae6175a8791": "legacy ipv4 1",
    "b4442579f88d79a55a51f426e6d937b1ec148d18096a03702602dd81b84221e7": "legacy ipv4 2",
    "fe09d7dea8456db7a7e32251eb4625f0f636f2e876a5f7a1a89b76a745aab807": "legacy ipv4 3",
    "1756f8b1d90d72515a92e18cc79a71d29e5afc9a3492663ea02244223d77f629": "legacy ipv4 4",
    "02ace098f65c06c9f5dfc7e5135cd70ac67794d8a53d89a4099054ec5a419a9d": "legacy ipv4 5",
    "af900ba67b372be89ec7efc24f5ac6641f97dbbb4976e17b7c4a87a18c531cd7": "legacy ipv4 6",
    "0bf18bb4d9601abc00b2699e93b595823948dd4ad34b6782a039ce49891a9182": "legacy ipv4 7",
    "52d99898433eea89726d7c187a7f701db279825038683a46248f1593e998c46e": "legacy ipv4 8",
    "f082d42a62a884acb72f04f614794e5834e61d3eb0f11fba9030139f30be6d1b": "legacy ipv4 9",
    "377eb79a80e4e449b30133312479bb81c3f2d6955c1c42c33c0632bd7348533e": "legacy ipv4 10",
    "3731fe80d5b5e6f7ff03472c8f661d638bdf85678a15e81ea3729ad63bd40a62": "legacy ipv4 11",
    "87537239ba73917cb27819825eb4c7934203b2b0da224e7f8e7b962fd4220a8c": "legacy ipv4 12",
    "811218882cdbe7479bf703ebe06eafc0516dd7d81d3f994c8f3eb9660f078e26": "legacy ipv4 13",
    "f10eef5a94a376e1ceb453f4bfefffa74891de95c49daeb98c426a4fdfc84d66": "legacy ipv4 14",
    "badfa0f8da346df71b3b9a718d84aacacf9381a41f2663e8cb9ad13f26503cc0": "legacy ipv4 15",
    "7304d4046075f3e4cefe9b093873ae6fe52f04cf17a763c921a2d24581307bc0": "legacy ipv4 16",
    "6ff145fb495be9bb885fc8e0502236c05b380d82000018650fe5e77e8e5c9aca": "legacy ipv4 17",
    "cdc773662f13d68a8e6011f2ef15694447ce93cb16a0f9eba5dc9dc3bd2ba2d0": "legacy ipv4 18",
    "a8eb4cac3678fad150fe8c5dda2dbbeeb037c671634d373efb80edb229be9a8a": "legacy ipv4 19",
    "67bb2e084c5fb7a846b33b88d6cf103cfb60589145618a0fac0b8f21214aadef": "legacy ipv4 20",
    "2819e8cc90fe9ed163d82d0d424b4c72bd78ab677f56ce6f62e46ba81080cb59": "legacy ipv4 21",
    "d3a7e447f7d9baf7966a3feb25799c84fe1dae482567f50b82a6bb9a0a040854": "legacy private ipv4 1",
    "62f3b58e684fa86d294268de2ae6b6f38e77cd4ab07b5274e0576dd51b7b20c9": "legacy private ipv4 2",
    "c4df7405ab0720922730c3b20fa8d93ca7432819c66be0e26713dc2587ebf632": "legacy private ipv4 3",
    "d794edacdab5566cb34ebda14854c219d8c1472e7750da988163f98d2969cec8": "legacy private ipv4 4",
    "d5c824b28cac2e758dc44c52ff7302ea01e5e4e235ed47bb62785ed99c1ac2ee": "legacy private ipv4 5",
    "3d56985a7fb178e8eb469ddb59bb65505aef642e7047e5cd54e1597e11ede3e8": "legacy private ipv4 6",
    "fe9973fd44d332ba9de9cdfd92f56c0b318ff0096916762befc1a79917ccd8bd": "legacy private ipv4 7",
}
FORBIDDEN_MAC_DIGESTS = {
    "1f7cb28dfc3f0c6f79def9278bf6ca52929bebfdf2530fc66f5594f501777b3e": "legacy endpoint mac 1",
    "28d1bb21798cce9a150d157d0499da8d7940d871a31f958e73a67007e56a4f3b": "legacy endpoint mac 2",
    "69d6f5559fa9426c89bc0135201b89ed23c0d2e4705057f3279de22c88094f53": "legacy endpoint mac 3",
    "1f93d5664308fd3980794cbc099317be0c33629f360b3b409c3eca5afb22d2e1": "legacy endpoint mac 4",
    "193cc893062b4579cd46643cdcdd9ab24d649d6339761d0e829f521bfe034425": "legacy endpoint mac 5",
    "4db715cf971e563bcbae97b59dac0d06eabd9dfd3248c1749dd445e716aed3d6": "legacy endpoint mac 6",
    "9f535a2ee93275a355e331ed114d696029d1c46394f5bd9229cf7ee262fadf55": "legacy endpoint mac 7",
    "0921ad782a405bee7178397ff4c0369994f85b433d2e217a42f5983c4897cd14": "legacy endpoint mac 8",
    "ed20adbd58da9f1a84d0da809a0925489660a531d948460ad3b7bd9720ef68a3": "legacy endpoint mac 9",
    "0c53b63579dd0078667fcb4ebe01aea197bc38fa6b42b369a541bc40c4412b24": "legacy endpoint mac 10",
    "c49f0e2685b7374d291f388f9a6a88e2846f8d4ccbf2ab6800cc8d3f9dc307dd": "legacy endpoint mac 11",
    "db6e461a16fcaad3d4dc37e90e5dc18d666f4e1cdcad66a2613e55b905b34a8d": "legacy endpoint mac 12",
    "92acd1fbc5b60c5a35cfb780d809a2c60c64273debda575aad85e0a82d7f0f81": "legacy endpoint mac 13",
    "82dc6703ce0dcfcb55bfa915f64f157aaa42dc52297f5a2d292b2f1fdefc1da2": "legacy endpoint mac 14",
    "f3dc03fcb875f7716e7ac1eafbc1723cce41df84d227bc24de414d1936e92483": "legacy endpoint mac 15",
    "063df74064ae3dd062162b9ce4341d02eeec081c8610b1231fd0be4078815a8e": "legacy endpoint mac 16",
    "a5e03e8eea392b398e48b778a38983b62b95b4d3fe5e68645521846f7e8b2a96": "legacy endpoint mac 17",
    "9cecc043bd8f0839b8d6661d1633e47256e2b664420f0b082dc429fd99461b35": "legacy endpoint mac 18",
    "02937af318519a0aa532f18c12e46fbe9cb7171b56c846d4c0176a81f5357e6a": "legacy wireless mac",
    "d09cbb779257640b68535bb51963fd10d16741bd8bfe4751872d6b197fa5bb2c": "legacy chassis mac 1",
    "d3ce4e704299cabe684924c5b396adb888ea538e223e639675a90deb1510d62b": "legacy chassis mac 2",
}
FORBIDDEN_RUN_DATE_DIGESTS = {
    "8083cc7f3ee042500b06e7c2c714644606c2fff450988ab1766743c807fb4225": "legacy compact run date 1",
    "eca80d2c229c876e91ede613422686e00a568dbd39073e63179bf5df1a45bed8": "legacy compact run date 2",
    "fb58a6f531bff246d99ef07d6688c7c8dcdc76ceb5d612e4e91f537458b14484": "legacy compact run date 3",
    "484a015aed069a8178020f8777f6a9a2f53e9abd2ce6f21f0e56410a5419798a": "legacy compact run date 4",
    "5b5ed8933b153378276dcfd5c6df34537695047e483a6b70b2dba62b8dee3f23": "legacy compact run date 5",
    "8fac15ddd13a8c7d5e8360ec14eac0c145aaa48deb01913c2a605bde51331b22": "legacy compact run date 6",
    "6c40e0ca62a7a7ef0d8952ccc8a9ce27f158fd6ce0b155e179672ea1bd895b21": "legacy compact run date 7",
    "6510b9a31deaa04d3d12d60b6afb1f364f8be3e34beb16bc202d3da4c4cb80be": "legacy compact run date 8",
    "ff9d914333c53b6e8aa0d8e5cf0d7469bdf5a657acbff5c54304577a80fe8ac7": "legacy compact run date 9",
    "1061e114e628d6bbc3211b89fd2b7a3cdb10fefb8fe89d2023a03105e65f5f07": "legacy compact run date 10",
    "cb4def806f2d2cb7ff614277f04a3cbdcb160470d9a177b23d8927d5c544669b": "legacy compact run date 11",
    "18ecd05cd87a1d5a244603ac7e3c63806f79674abcbbbe952dff8b717a12697c": "legacy compact run date 12",
}

COMPONENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|gov|edu|mil|int|local|example)\b"
)
IPV4_RE = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
IPV6_TOKEN_RE = re.compile(r"(?i)(?<![0-9a-f:])[0-9a-f:]*:[0-9a-f:]+(?![0-9a-f:])")
MACISH_RE = re.compile(r"(?i)(?:SEP|AP)?[0-9a-f][0-9a-f.:-]{10,20}")
COMPACT_RUN_DATE_RE = re.compile(r"\b(20[0-9]{6})-")

DOCUMENTATION_PATHS = {ROOT / "README.md", ROOT / "CHANGELOG.md"}
DOCUMENTATION_PATHS.update((ROOT / "docs").rglob("*.md"))
APPROVED_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "192.0.2.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)
APPROVED_EXTERNAL_DOMAINS = (
    "github.com",
    "packaging.python.org",
    "peps.python.org",
    "pypa.io",
    "python.org",
    "pytest.org",
)
APPROVED_EXAMPLE_DOMAINS = ("example", "example.com", "example.net", "example.org")


def _digest(value: str) -> str:
    """Return a stable case-insensitive fingerprint for one candidate value."""

    return sha256(value.casefold().encode("utf-8")).hexdigest()


def _text_files() -> list[Path]:
    """Return shipped UTF-8 files while excluding generated and binary state."""

    paths: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRECTORY_NAMES for part in path.parts):
            continue
        try:
            path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        paths.append(path)
    return sorted(paths)


def _ip_literals(text: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Extract parseable IP literals without mistaking OIDs for addresses."""

    values: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for raw in IPV4_RE.findall(text):
        try:
            values.add(ipaddress.ip_address(raw))
        except ValueError:
            continue
    for raw in IPV6_TOKEN_RE.findall(text):
        try:
            values.add(ipaddress.ip_address(raw.strip("[]")))
        except ValueError:
            continue
    return values


def test_removed_operation_identifiers_do_not_return() -> None:
    """Reject readable and alternate-form versions of removed identifiers."""

    violations: list[str] = []
    for path in _text_files():
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)

        for component in COMPONENT_RE.findall(text):
            folded = component.casefold()
            label = FORBIDDEN_COMPONENT_DIGESTS.get(_digest(folded))
            if label:
                violations.append(f"{relative}: {label}")
            for (length, prefix_digest), prefix_label in FORBIDDEN_PREFIX_DIGESTS.items():
                if len(folded) >= length and _digest(folded[:length]) == prefix_digest:
                    violations.append(f"{relative}: {prefix_label}")

        for domain in DOMAIN_RE.findall(text):
            labels = domain.casefold().split(".")
            for index in range(len(labels)):
                suffix = ".".join(labels[index:])
                label = FORBIDDEN_DOMAIN_SUFFIX_DIGESTS.get(_digest(suffix))
                if label:
                    violations.append(f"{relative}: {label}")

        for address in _ip_literals(text):
            label = FORBIDDEN_IP_DIGESTS.get(_digest(str(address)))
            if label:
                violations.append(f"{relative}: {label}")

        for raw in MACISH_RE.findall(text):
            folded = raw.casefold()
            if folded.startswith("sep"):
                folded = folded[3:]
            elif folded.startswith("ap"):
                folded = folded[2:]
            compact = re.sub(r"[^0-9a-f]", "", folded)
            for index in range(max(1, len(compact) - 11)):
                candidate = compact[index : index + 12]
                if len(candidate) != 12:
                    continue
                label = FORBIDDEN_MAC_DIGESTS.get(_digest(candidate))
                if label:
                    violations.append(f"{relative}: {label}")

        for compact_date in COMPACT_RUN_DATE_RE.findall(text):
            label = FORBIDDEN_RUN_DATE_DIGESTS.get(_digest(compact_date))
            if label:
                violations.append(f"{relative}: {label}")

    assert not violations, "operation-derived identifiers found:\n" + "\n".join(
        sorted(set(violations))
    )


def test_operator_documentation_uses_safe_example_namespaces() -> None:
    """Keep documentation addresses and domains in explicit example namespaces."""

    violations: list[str] = []
    for path in sorted(DOCUMENTATION_PATHS):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)
        for address in _ip_literals(text):
            if not any(address in network for network in APPROVED_DOCUMENTATION_NETWORKS):
                violations.append(f"{relative}: non-example IP address")

        for domain in DOMAIN_RE.findall(text):
            folded = domain.casefold().rstrip(".")
            if any(
                folded == suffix or folded.endswith(f".{suffix}")
                for suffix in APPROVED_EXAMPLE_DOMAINS + APPROVED_EXTERNAL_DOMAINS
            ):
                continue
            violations.append(f"{relative}: non-example domain {folded}")

    assert not violations, "unsafe documentation examples found:\n" + "\n".join(
        sorted(set(violations))
    )
