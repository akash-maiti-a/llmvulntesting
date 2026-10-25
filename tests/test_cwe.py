from vulnscan.cwe import family, normalize, same_family


def test_normalize_picks_first_cwe_from_string_or_list():
    assert normalize(["CWE-78: OS Command Injection", "CWE-94"]) == "CWE-78"
    assert normalize("cwe-89 sql") == "CWE-89"
    assert normalize(None) == "CWE-UNKNOWN"


def test_families_group_equivalent_cwes():
    assert same_family("CWE-78", "CWE-77")
    assert same_family("CWE-98", "CWE-22")
    assert not same_family("CWE-79", "CWE-89")


def test_unknown_cwe_is_its_own_family():
    assert family("CWE-1234") == "CWE-1234"
    assert not same_family("CWE-1234", "CWE-89")
