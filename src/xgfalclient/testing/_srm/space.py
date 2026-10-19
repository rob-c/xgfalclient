"""The test SRM server's space-token operations: ``srmGetSpaceTokens``, ``srmGetSpaceMetaData``.

Both answer from the server's :attr:`spaces` table of :class:`~.model.Space`
reservations, which a test fills in. The table is also what
a get, put or bring-online's ``targetSpaceToken`` is checked against
(in :mod:`.requests`); nothing here reserves or accounts space.
"""

from __future__ import annotations

from ...plugins.srm import soap
from .base import _OperationsBase
from .model import Fields, _aggregate, _only, _status


class _SpaceOps(_OperationsBase):
    """Space-token lookups."""

    # -- space ---------------------------------------------------------------------

    def _srmGetSpaceTokens(self, part: soap.Node) -> Fields:
        """The tokens whose description is ``userSpaceTokenDescription``, or all of them.

        No match is ``SRM_INVALID_REQUEST``; the tokens come out sorted.
        """
        description = part.get("userSpaceTokenDescription")
        tokens = [
            token
            for token, space in sorted(self.spaces.items())
            if not description or space.description == description
        ]
        if not tokens:
            return _only("SRM_INVALID_REQUEST", "No such space token descriptor")
        return [
            ("returnStatus", _status("SRM_SUCCESS")),
            ("arrayOfSpaceTokens", [("stringArray", token) for token in tokens]),
        ]

    def _srmGetSpaceMetaData(self, part: soap.Node) -> Fields:
        """A ``TMetaDataSpace`` per requested token; unknown ones get their own error status.

        ``lifetimeLeft`` is reported equal to ``lifetimeAssigned``: time does
        not pass for these reservations.
        """
        details: Fields = []
        codes = []
        for token in part.strings("arrayOfSpaceTokens", "stringArray"):
            space = self.spaces.get(token)
            if space is None:
                codes.append("SRM_INVALID_REQUEST")
                unknown = _status("SRM_INVALID_REQUEST", "No such space token")
                details.append(("spaceDataArray", [("spaceToken", token), ("status", unknown)]))
                continue
            codes.append("SRM_SUCCESS")
            policy = [("retentionPolicy", space.retention), ("accessLatency", space.latency)]
            entry = [
                ("spaceToken", token),
                ("status", _status("SRM_SUCCESS")),
                ("retentionPolicyInfo", policy),
                ("owner", space.owner),
                ("totalSize", space.total),
                ("guaranteedSize", space.guaranteed),
                ("unusedSize", space.unused),
                ("lifetimeAssigned", space.lifetime),
                ("lifetimeLeft", space.lifetime),
            ]
            details.append(("spaceDataArray", entry))
        return [("returnStatus", _status(_aggregate(codes))), ("arrayOfSpaceDetails", details)]
