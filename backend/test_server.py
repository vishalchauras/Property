import unittest
from datetime import datetime, timezone

from pydantic import ValidationError

from server import (
    OTPRequest,
    CommentInput,
    PropertyInput,
    ReelInput,
    Role,
    app,
    clean,
    issue_token,
)
import jwt


class InputValidationTests(unittest.TestCase):
    def test_phone_number_is_trimmed_and_validated(self):
        self.assertEqual(OTPRequest(phone=" +919876543210 ").phone, "+919876543210")
        with self.assertRaises(ValidationError):
            OTPRequest(phone="abc")

    def test_listing_requires_positive_price(self):
        with self.assertRaises(ValidationError):
            PropertyInput(title="Home", price=0, city="Pune", locality="Kothrud")
        with self.assertRaises(ValidationError):
            PropertyInput(title="   ", price=1000, city="Pune", locality="Kothrud")

    def test_reel_only_accepts_http_media_urls(self):
        reel = ReelInput(title="Tour", media_url="https://example.com/tour.mp4")
        self.assertEqual(reel.media_url, "https://example.com/tour.mp4")
        with self.assertRaises(ValidationError):
            ReelInput(title="Tour", media_url="javascript:alert(1)")
        with self.assertRaises(ValidationError):
            ReelInput(title="Tour", media_url="https:///missing-host")

    def test_comment_cannot_be_only_whitespace(self):
        with self.assertRaises(ValidationError):
            CommentInput(text="   ")


class SerializationAndContractTests(unittest.TestCase):
    def test_clean_converts_nested_ids_and_dates(self):
        timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
        result = clean({"_id": "item-1", "created_at": timestamp, "owner": {"_id": "user-1"}})
        self.assertEqual(result["id"], "item-1")
        self.assertEqual(result["owner"]["id"], "user-1")
        self.assertEqual(result["created_at"], timestamp.isoformat())

    def test_access_token_contains_user_subject(self):
        token = issue_token("user-1")
        payload = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(payload["sub"], "user-1")
        self.assertIn("exp", payload)

    def test_required_api_surfaces_are_registered(self):
        paths = {route.path for route in app.routes}
        for path in (
            "/api/v1/auth/request-otp",
            "/api/v1/properties",
            "/api/v1/reels/{reel_id}/comments",
            "/api/v1/enquiries",
            "/api/v1/leads/{lead_id}/status",
            "/api/v1/admin/overview",
            "/api/v1/admin/users/pending",
            "/api/v1/analytics/events",
        ):
            self.assertIn(path, paths)

    def test_public_registration_roles_cannot_assign_admin(self):
        self.assertEqual({role.value for role in Role}, {"customer", "owner", "broker"})


if __name__ == "__main__":
    unittest.main()
