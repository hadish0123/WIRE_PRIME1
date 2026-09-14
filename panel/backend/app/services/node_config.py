import io
import re
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote

import segno

from app.crypto import (
    AWGClientConfig,
    _build_amnezia_config_json,
    build_amnezia_qr_chunks,
    build_amnezia_vpn_uri,
    build_client_config,
)
from app.models import Node, Peer


class ClientIdentity(Protocol):
    """The credential-bearing owner of a client configuration.

    Both the frozen legacy ``User`` key columns and a ``Device`` satisfy this structurally, so the
    builders serve either one without inventing a synthetic ``User``. Everything a config needs
    (keypair, VPN IP, display name) lives here; nothing about ownership, limits or lifecycle does.
    """

    id: str
    name: str
    public_key: str | None
    private_key: str | None
    vpn_ip: str | None


_NODE_VPN_ADDRESS = '10.8.0.1/24'
_POST_UP = (
    'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j MASQUERADE; '
    'iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT'
)
_POST_DOWN = (
    'iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -j MASQUERADE; '
    'iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT'
)


@dataclass(frozen=True)
class QRStyle:
    error: str
    scale: int
    border: int
    dark: str
    light: str = '#ffffff'


def node_kwargs(node: Node) -> dict[str, Any]:
    return {
        'jc': node.jc or 4,
        'jmin': node.jmin or 40,
        'jmax': node.jmax or 70,
        's1': node.s1 or 0,
        's2': node.s2 or 0,
        's3': node.s3 or 0,
        's4': node.s4 or 0,
        'h1': node.h1 or '1',
        'h2': node.h2 or '2',
        'h3': node.h3 or '3',
        'h4': node.h4 or '4',
        'i1': node.i1 or '',
        'i2': node.i2 or '',
        'i3': node.i3 or '',
        'i4': node.i4 or '',
        'i5': node.i5 or '',
    }


def node_mtu(node: Node) -> str:
    return node.mtu or '1376'


def build_awg_client_config(identity: ClientIdentity, node: Node, psk_key: str = '') -> str | None:
    server_public_key = node.server_public_key
    server_endpoint = node.server_endpoint
    private_key = identity.private_key
    vpn_ip = identity.vpn_ip
    if not server_public_key or not server_endpoint or not private_key or not vpn_ip:
        return None
    return build_client_config(
        AWGClientConfig(
            private_key=private_key,
            vpn_ip=vpn_ip,
            node_public_key=server_public_key,
            node_endpoint=server_endpoint,
            psk_key=psk_key,
            **node_kwargs(node),
        )
    )


def build_amnezia_client_config(
    identity: ClientIdentity,
    node: Node,
    description: str,
    psk_key: str = '',
    *,
    dns: str = '1.1.1.1',
) -> AWGClientConfig | None:
    server_public_key = node.server_public_key
    server_endpoint = node.server_endpoint
    private_key = identity.private_key
    vpn_ip = identity.vpn_ip
    if not server_public_key or not server_endpoint or not private_key or not vpn_ip:
        return None
    return AWGClientConfig(
        private_key=private_key,
        public_key=identity.public_key or '',
        vpn_ip=vpn_ip,
        node_public_key=server_public_key,
        node_endpoint=server_endpoint,
        dns=dns,
        description=description,
        psk_key=psk_key,
        mtu=node_mtu(node),
        **node_kwargs(node),
    )


def build_user_amnezia_qr_chunks(
    identity: ClientIdentity,
    node: Node,
    description: str,
    psk_key: str = '',
) -> list[str] | None:
    config = build_amnezia_client_config(identity, node, description, psk_key)
    return build_amnezia_qr_chunks(config) if config else None


def build_user_amnezia_vpn_uri(
    identity: ClientIdentity,
    node: Node,
    description: str,
    psk_key: str = '',
) -> str | None:
    config = build_amnezia_client_config(identity, node, description, psk_key)
    return build_amnezia_vpn_uri(config) if config else None


def build_user_amnezia_config_json(
    identity: ClientIdentity,
    node: Node,
    description: str,
    psk_key: str = '',
) -> bytes | None:
    config = build_amnezia_client_config(identity, node, description, psk_key, dns='1.1.1.1')
    return _build_amnezia_config_json(config) if config else None


def make_qr_svg(
    data: str,
    style: QRStyle,
) -> bytes:
    buf = io.BytesIO()
    segno.make(data, error=style.error).save(
        buf,
        kind='svg',
        scale=style.scale,
        border=style.border,
        svgclass=None,
        lineclass=None,
        dark=style.dark,
        light=style.light,
    )
    return buf.getvalue()


def make_awg_qr_svg(
    identity: ClientIdentity,
    node: Node,
    psk_key: str = '',
    *,
    style: QRStyle,
) -> bytes | None:
    config = build_awg_client_config(identity, node, psk_key)
    if not config:
        return None
    return make_qr_svg(config, style)


def make_amnezia_qr_svg(
    identity: ClientIdentity,
    node: Node,
    description: str,
    psk_key: str = '',
    *,
    style: QRStyle,
) -> bytes | None:
    chunks = build_user_amnezia_qr_chunks(identity, node, description, psk_key)
    if not chunks or len(chunks) > 1:
        return None
    return make_qr_svg(chunks[0], style)


_ARCHIVE_UNSAFE = re.compile(r'[^A-Za-z0-9._-]+')
_MAX_ARCHIVE_COMPONENT = 64
_MIN_LOOP_GUARD = 2


def archive_component(raw: str, *, fallback: str) -> str:
    """One safe path component for an archive entry.

    Device and node names are user-controlled (Unicode allowed), so separators, spaces and control
    characters cannot be carried into a ZIP entry name: unsafe runs collapse into ``_``. The result
    is never empty and never contains a path separator, so an entry can only land directly inside
    the folder this module chose for it.
    """
    cleaned = _ARCHIVE_UNSAFE.sub('_', raw).strip('._')[:_MAX_ARCHIVE_COMPONENT]
    return cleaned or fallback


def unique_archive_name(used: set[str], preferred: str) -> str:
    """``preferred`` when free, otherwise the same name with a numeric suffix; records the result.

    Name uniqueness is not guaranteed by the data - two devices may share a name, and so may two
    nodes - while a ZIP with duplicate entry names is unusable. Callers pass the full entry path, so
    the guarantee covers folders as well as files.
    """
    if preferred not in used:
        used.add(preferred)
        return preferred
    stem, dot, extension = preferred.rpartition('.')
    if not dot:
        stem, extension = preferred, ''
    counter = _MIN_LOOP_GUARD
    while True:
        candidate = f'{stem}-{counter}{dot}{extension}' if dot else f'{stem}-{counter}'
        if candidate not in used:
            used.add(candidate)
            return candidate
        counter += 1


def device_archive_folder(device: ClientIdentity) -> str:
    """Per-device folder for a multi-device archive: the name plus a piece of the device id.

    The id fragment is what makes the folder unique, because the visible name is not: it is also
    what identifies the device in the archive after a rename.
    """
    return f'{archive_component(device.name, fallback="device")}-{device.id[:8]}'


def config_entry_name(device: ClientIdentity, node: Node, *, folder: str | None = None) -> str:
    """Entry path for one device's config on one node, optionally inside a per-device folder."""
    filename = (
        f'{archive_component(device.name, fallback="device")}-'
        f'{archive_component(node.name, fallback="node")}.conf'
    )
    return f'{folder}/{filename}' if folder else filename


@dataclass(frozen=True)
class ConfigZipEntry:
    """One config to place in an archive: the device/node/peer it is built from, and its name."""

    device: ClientIdentity
    node: Node
    peer: Peer
    name: str


def build_configs_zip(entries: Iterable[ConfigZipEntry]) -> io.BytesIO:
    """A ZIP of the given configs, with every entry name guaranteed unique.

    Callers decide *which* configs are ready (their device/node readiness rule lives in
    ``app.services.devices``); this function only renders them. A config that cannot be built from
    the entry's rows is skipped, never written empty.
    """
    buf = io.BytesIO()
    used: set[str] = set()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as archive:
        for entry in entries:
            config = build_awg_client_config(entry.device, entry.node, entry.peer.psk_key or '')
            if not config:
                continue
            archive.writestr(unique_archive_name(used, entry.name), config)
    buf.seek(0)
    return buf


def attachment_headers(filename: str) -> dict[str, str]:
    """A ``Content-Disposition`` that survives quotes, slashes and non-ASCII names.

    The quoted ASCII fallback is stripped of anything a header cannot carry, and the full name is
    also sent RFC 5987-encoded so clients keep the device's real Unicode name.
    """
    fallback = re.sub(r'[^A-Za-z0-9._-]+', '_', filename).strip('_') or 'config'
    return {
        'Content-Disposition': (
            f'attachment; filename="{fallback}"; filename*=UTF-8\'\'{quote(filename, safe="")}'
        )
    }


def node_interface(node: Node) -> dict[str, Any]:
    return {
        'private_key': node.private_key,
        'address': _NODE_VPN_ADDRESS,
        'listen_port': node.listen_port or 51820,
        **node_kwargs(node),
        'mtu': node_mtu(node),
        'post_up': _POST_UP,
        'post_down': _POST_DOWN,
    }


def peer_payload(peer: Peer) -> dict[str, Any] | None:
    """Desired node-side peer for a device; ``None`` when the device has no usable identity."""
    user = peer.user
    device = peer.device
    if not device.public_key or not device.vpn_ip:
        return None
    return {
        'peer_id': peer.id,
        'user_id': user.id,
        'user_name': user.name,
        'device_id': device.id,
        'device_name': device.name,
        'public_key': device.public_key,
        'allowed_ip': device.vpn_ip,
        'psk_key': peer.psk_key or '',
        'status': peer.status,
        'is_blocked': user.is_blocked,
    }


def node_snapshot(node: Node, peers: list[Peer]) -> dict[str, Any]:
    return {
        'id': node.id,
        'name': node.name,
        'url': node.url,
        'token': node.token,
        'provision_status': node.provision_status,
        'interface': node_interface(node),
        'peers': [payload for peer in peers if (payload := peer_payload(peer))],
    }
