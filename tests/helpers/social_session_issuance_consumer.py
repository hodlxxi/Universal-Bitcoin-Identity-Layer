"""Test-only substitute for the later Social BFF; never a production store.

The source fixture pins Social's actual subject/viewerAccessToken consumer
shape. The DB remains the sole one-shot owner even if this local record is lost.
"""

from datetime import datetime, timezone


def milliseconds(value):
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp() * 1000)


class SocialConsumer:
    def __init__(self, post, now):
        self.post, self.now = post, now
        self.record = None

    def materialize(self, delivery):
        if delivery["currentActive"] is not True:
            raise ValueError("authentication unavailable")
        receipt = delivery["receipt"]
        current = self.post("resolve", {"issuanceId": receipt["issuanceId"]}, viewer=delivery["viewerAccessToken"])
        if current.status_code != 200 or current.get_json()["receipt"] != receipt:
            raise ValueError("authentication unavailable")
        result = current.get_json()
        if result["subject"] != delivery["subject"] or not self.now() < milliseconds(receipt["expiresAt"]):
            raise ValueError("authentication unavailable")
        self.record = dict(
            subject=result["subject"],
            viewerAccessToken=delivery["viewerAccessToken"],
            issuanceId=receipt["issuanceId"],
            issuedAt=milliseconds(receipt["issuedAt"]),
            expiresAt=milliseconds(receipt["expiresAt"]),
        )
        return self.record

    def authenticated_session(self):
        if self.record is None or not self.now() < self.record["expiresAt"]:
            raise ValueError("authentication unavailable")
        result = self.post(
            "resolve", {"issuanceId": self.record["issuanceId"]}, viewer=self.record["viewerAccessToken"]
        )
        if result.status_code != 200 or result.get_json()["subject"] != self.record["subject"]:
            raise ValueError("authentication unavailable")
        return self.record

    def logout(self):
        if self.record is None:
            raise ValueError("authentication unavailable")
        result = self.post("revoke", {"issuanceId": self.record["issuanceId"]}, viewer=self.record["viewerAccessToken"])
        if result.status_code != 200:
            raise ValueError("logout acknowledgement unavailable")
        self.record = None
