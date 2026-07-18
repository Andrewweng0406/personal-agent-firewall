import chromadb
import pytest

from app.privacy.vector_store import SemanticPiiDetector


@pytest.fixture(scope="module")
def detector() -> SemanticPiiDetector:
    # Isolated in-memory client per test module so seeding doesn't collide
    # with any other collection of the same name in the process.
    return SemanticPiiDetector(client=chromadb.Client())


def test_detects_natural_language_secret_with_no_fixed_format(detector):
    assert detector.is_sensitive(
        "Here is my private key for the crypto wallet, please keep it safe"
    )


def test_detects_financial_identifier(detector):
    assert detector.is_sensitive("my bank account routing number is 021000021")


def test_does_not_flag_benign_frontend_task(detector):
    assert not detector.is_sensitive(
        "The button should be blue and rounded for the login page"
    )


def test_detects_bulk_customer_pii_list(detector):
    assert detector.is_sensitive(
        "Attached is the customer list with emails and phone numbers"
    )


def test_does_not_flag_benign_code(detector):
    assert not detector.is_sensitive("export const LoginButton = () => null;")


def test_does_not_flag_routine_project_talk(detector):
    assert not detector.is_sensitive(
        "the deployment pipeline needs a review before merging"
    )


def test_empty_text_is_not_sensitive(detector):
    assert not detector.is_sensitive("")
    assert not detector.is_sensitive("   ")
