import unittest

from backend.quality_metrics import build_quality_metrics, website_presence_category


class QualityMetricsTests(unittest.TestCase):
    def test_website_presence_does_not_infer_absence_from_unverified_business(self):
        self.assertEqual(
            website_presence_category(None, {"status": "not_verified"}, search_completed=True),
            "unknown",
        )

    def test_verified_no_website_is_explicitly_bounded_search_result(self):
        self.assertEqual(
            website_presence_category(None, {"status": "verified"}, search_completed=True),
            "no_website_found",
        )
        self.assertEqual(
            website_presence_category(None, {"status": "verified"}, search_completed=False),
            "unknown",
        )

    def test_identity_confusion_matrix_and_rates(self):
        rows = [
            {"industry": "restaurant", "location": "Nairobi", "predicted_identity_verified": 1,
             "ground_truth_identity": "exists"},
            {"industry": "restaurant", "location": "Nairobi", "predicted_identity_verified": 1,
             "ground_truth_identity": "does_not_exist"},
            {"industry": "salon", "location": "Kisumu", "predicted_identity_verified": 0,
             "ground_truth_identity": "exists"},
            {"industry": "salon", "location": "Kisumu", "predicted_identity_verified": 0,
             "ground_truth_identity": "does_not_exist"},
            {"industry": "salon", "location": "Kisumu", "predicted_identity_verified": 0,
             "ground_truth_identity": "unknown"},
        ]
        result = build_quality_metrics(rows)
        identity = result["overall"]["identity_verification"]
        self.assertEqual(identity["true_positive"], 1)
        self.assertEqual(identity["false_positive"], 1)
        self.assertEqual(identity["false_negative"], 1)
        self.assertEqual(identity["true_negative"], 1)
        self.assertEqual(identity["unscored_predictions"], 1)
        self.assertEqual(identity["accuracy"], 0.5)
        self.assertEqual(identity["precision"], 0.5)
        self.assertEqual(identity["recall"], 0.5)
        self.assertEqual(result["by_industry"][0]["industry"], "restaurant")
        self.assertEqual(result["by_location"][1]["location"], "Nairobi")

    def test_website_status_and_contact_accuracy_exclude_unreviewed_values(self):
        rows = [
            {"industry": "retail", "location": "Mombasa",
             "predicted_identity_verified": True, "ground_truth_identity": "exists",
             "predicted_website_presence": "website_found",
             "ground_truth_website_presence": "website_found",
             "predicted_website_state": "working", "ground_truth_website_state": "broken",
             "predicted_contact_email": "hello@example.test",
             "ground_truth_email_correct": False,
             "predicted_contact_phone": "+254700000000",
             "ground_truth_phone_correct": True},
            {"industry": "retail", "location": "Mombasa",
             "predicted_identity_verified": True, "ground_truth_identity": "exists",
             "predicted_website_presence": "no_website_found",
             "ground_truth_website_presence": "no_website_found",
             "predicted_website_state": "unknown", "ground_truth_website_state": "not_assessed",
             "predicted_contact_email": "unreviewed@example.test",
             "ground_truth_email_correct": None,
             "predicted_contact_phone": None,
             "ground_truth_phone_correct": None},
        ]
        metrics = build_quality_metrics(rows)["overall"]
        self.assertEqual(metrics["website_presence"]["accuracy"], 1.0)
        self.assertEqual(metrics["website_status"]["accuracy"], 0.0)
        self.assertEqual(metrics["contact_data"]["email"]["accuracy"], 0.0)
        self.assertEqual(metrics["contact_data"]["email"]["not_reviewed"], 1)
        self.assertEqual(metrics["contact_data"]["phone"]["accuracy"], 1.0)

    def test_empty_dataset_reports_null_rates_not_perfect_accuracy(self):
        metrics = build_quality_metrics([])["overall"]
        self.assertIsNone(metrics["identity_verification"]["accuracy"])
        self.assertIsNone(metrics["website_presence"]["precision"])
        self.assertEqual(metrics["samples"], 0)


if __name__ == "__main__":
    unittest.main()
