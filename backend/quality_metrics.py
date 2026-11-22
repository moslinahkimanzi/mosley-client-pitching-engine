"""Per-workspace quality evaluation metrics for labelled MCAS prospect samples.

Unknown and unreviewed truth values are excluded from metric denominators and
reported explicitly. Metrics are counts and descriptive statistics, not claims
of population-wide accuracy.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable


IDENTITY_TRUTH = {"exists", "does_not_exist", "unknown"}
PRESENCE_TRUTH = {"website_found", "no_website_found", "unknown"}
WEBSITE_STATES = {"working", "broken", "needs_improvement", "access_restricted"}


def website_presence_category(
    website: str | None,
    verification: dict,
    *,
    search_completed: bool,
) -> str:
    """Classify the observed website evidence, without claiming global absence."""
    if verification.get("status") != "verified":
        return "unknown"
    if website:
        if verification.get("website_identity_match") or verification.get("website_domain_corroborated"):
            return "website_found"
        return "unknown"
    # "no_website_found" means no official website was found in this bounded
    # research run, not proof that the business has no website anywhere.
    return "no_website_found" if search_completed else "unknown"


RESEARCH_GROUP_KEYS = ("website_found", "no_website_found", "broken_website")


def classify_research_group(
    verification: dict,
    website_presence: str,
    website_state: str,
    website_audit: dict | None = None,
) -> str | None:
    """Assign a verified candidate to one of three evidence-backed groups.

    Ambiguous/restricted/error states abstain rather than being forced into a
    convenient category. A broken site needs two 404/410 checks and a domain
    linked to the verified business identity.
    """
    website_audit = website_audit or {}
    if verification.get("status") != "verified":
        return None
    if website_state == "broken":
        linked = bool(
            verification.get("website_identity_match")
            or verification.get("website_domain_corroborated")
        )
        confirmed = int(website_audit.get("confirmed_unavailable_checks") or 0) >= 2
        return "broken_website" if linked and confirmed else None
    if website_presence == "no_website_found" and website_state == "not_listed":
        return "no_website_found"
    if website_presence == "website_found" and website_state in {
        "working", "needs_improvement", "access_restricted"
    }:
        return "website_found"
    return None


def select_balanced_research_results(records: Iterable[dict], target_per_group: int) -> dict:
    """Select the same number from each group, never padding or relabelling.

    The number returned per group is the minimum of the requested target and
    the smallest verified group. Surplus and unclassified candidates remain
    separately available for transparent reporting.
    """
    buckets = {key: [] for key in RESEARCH_GROUP_KEYS}
    for record in records:
        key = record.get("research_group")
        if key in buckets and record.get("verified") and record.get("saved"):
            buckets[key].append(dict(record))
    available = {key: len(value) for key, value in buckets.items()}
    balanced_count = min([target_per_group, *available.values()])
    selected = []
    selected_ids = set()
    for key in RESEARCH_GROUP_KEYS:
        for record in buckets[key][:balanced_count]:
            record["balanced_group"] = key
            selected.append(record)
            selected_ids.add(record.get("validation_sample_id"))
    selected.sort(key=lambda item: (
        RESEARCH_GROUP_KEYS.index(item.get("research_group"))
        if item.get("research_group") in RESEARCH_GROUP_KEYS else 99,
        item.get("name", "").casefold(),
    ))
    additional = [
        dict(record) for record in records
        if record.get("validation_sample_id") not in selected_ids
    ]
    return {
        "balanced_per_group": balanced_count,
        "available_by_group": available,
        "balanced_results": selected,
        "additional_results": additional,
        "shortfalls": {
            key: max(0, target_per_group - available[key])
            for key in RESEARCH_GROUP_KEYS
        },
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _binary_metrics(tp: int, fp: int, fn: int, tn: int, unscored: int = 0) -> dict:
    compared = tp + fp + fn + tn
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "unscored_predictions": unscored,
        "compared": compared,
        "accuracy": _ratio(tp + tn, compared),
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "specificity": _ratio(tn, tn + fp),
        "false_positive_rate": _ratio(fp, fp + tn),
        "false_negative_rate": _ratio(fn, fn + tp),
    }


def _metrics_for(records: list[dict]) -> dict:
    tp = fp = fn = tn = identity_unscored = 0
    wtp = wfp = wfn = wtn = website_unscored = 0
    status_correct = status_compared = status_unscored = 0
    email_correct = email_incorrect = email_unreviewed = email_present = 0
    phone_correct = phone_incorrect = phone_unreviewed = phone_present = 0
    labelled_identity = labelled_presence = 0

    for row in records:
        truth_identity = row.get("ground_truth_identity") or "unknown"
        predicted_identity = bool(row.get("predicted_identity_verified"))
        if truth_identity in {"exists", "does_not_exist"}:
            labelled_identity += 1
            if truth_identity == "exists":
                if predicted_identity:
                    tp += 1
                else:
                    fn += 1
            elif predicted_identity:
                fp += 1
            else:
                tn += 1
        else:
            identity_unscored += 1

        truth_presence = row.get("ground_truth_website_presence") or "unknown"
        predicted_presence = row.get("predicted_website_presence") or "unknown"
        if truth_presence in {"website_found", "no_website_found"}:
            labelled_presence += 1
            if predicted_presence == "website_found":
                if truth_presence == "website_found":
                    wtp += 1
                else:
                    wfp += 1
            elif predicted_presence == "no_website_found":
                if truth_presence == "website_found":
                    wfn += 1
                else:
                    wtn += 1
            else:
                website_unscored += 1
        else:
            website_unscored += 1

        truth_state = row.get("ground_truth_website_state") or "not_assessed"
        predicted_state = row.get("predicted_website_state") or "unknown"
        if truth_state in WEBSITE_STATES:
            if predicted_state in WEBSITE_STATES:
                status_compared += 1
                if truth_state == predicted_state:
                    status_correct += 1
            else:
                status_unscored += 1

        if row.get("predicted_contact_email"):
            email_present += 1
            if row.get("ground_truth_email_correct") is None:
                email_unreviewed += 1
            elif bool(row.get("ground_truth_email_correct")):
                email_correct += 1
            else:
                email_incorrect += 1

        if row.get("predicted_contact_phone"):
            phone_present += 1
            if row.get("ground_truth_phone_correct") is None:
                phone_unreviewed += 1
            elif bool(row.get("ground_truth_phone_correct")):
                phone_correct += 1
            else:
                phone_incorrect += 1

    email_audited = email_correct + email_incorrect
    phone_audited = phone_correct + phone_incorrect
    return {
        "samples": len(records),
        "labelled_identity_samples": labelled_identity,
        "labelled_website_presence_samples": labelled_presence,
        "identity_verification": _binary_metrics(tp, fp, fn, tn, identity_unscored),
        "website_presence": {
            **_binary_metrics(wtp, wfp, wfn, wtn, website_unscored),
            "positive_class": "website_found",
        },
        "website_status": {
            "correct": status_correct,
            "incorrect": status_compared - status_correct,
            "compared": status_compared,
            "unscored": status_unscored,
            "accuracy": _ratio(status_correct, status_compared),
        },
        "contact_data": {
            "email": {
                "present": email_present,
                "correct": email_correct,
                "incorrect": email_incorrect,
                "reviewed": email_audited,
                "not_reviewed": email_unreviewed,
                "accuracy": _ratio(email_correct, email_audited),
            },
            "phone": {
                "present": phone_present,
                "correct": phone_correct,
                "incorrect": phone_incorrect,
                "reviewed": phone_audited,
                "not_reviewed": phone_unreviewed,
                "accuracy": _ratio(phone_correct, phone_audited),
            },
        },
        "measurement_note": (
            "Only independently labelled ground-truth records enter metric denominators. "
            "Unknown, unreviewed and abstained predictions are counted separately. "
            "Rates describe this workspace's reviewed sample, not all businesses in a market."
        ),
    }


def build_quality_metrics(records: Iterable[dict]) -> dict:
    """Return overall and industry/location-stratified validation metrics."""
    rows = [dict(row) for row in records]
    by_industry: dict[str, list[dict]] = defaultdict(list)
    by_location: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_industry[str(row.get("industry") or "unknown")].append(row)
        by_location[str(row.get("location") or "unknown")].append(row)
    return {
        "overall": _metrics_for(rows),
        "by_industry": [
            {"industry": key, **_metrics_for(value)}
            for key, value in sorted(by_industry.items())
        ],
        "by_location": [
            {"location": key, **_metrics_for(value)}
            for key, value in sorted(by_location.items())
        ],
    }
