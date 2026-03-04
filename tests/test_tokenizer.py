"""Tests for the Tokenizer."""

from scrubjay.core.tokenizer import Tokenizer
from scrubjay.core.types import FieldType


class TestTokenizerDeterminism:
    def test_same_input_same_output(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("jsmith", FieldType.USERNAME)
        r2 = t.generate("jsmith", FieldType.USERNAME)
        assert r1 == r2

    def test_different_inputs_different_outputs(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("jsmith", FieldType.USERNAME)
        r2 = t.generate("ajonas", FieldType.USERNAME)
        assert r1 != r2


class TestEmail:
    def test_basic_email(self):
        t = Tokenizer(seed="test")
        result = t.generate("jsmith@company.com", FieldType.EMAIL)
        assert "@" in result
        assert result.startswith("USER-")
        assert ".com" in result

    def test_preserves_domain_consistency(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("alice@company.com", FieldType.EMAIL)
        r2 = t.generate("bob@company.com", FieldType.EMAIL)
        domain1 = r1.split("@")[1]
        domain2 = r2.split("@")[1]
        assert domain1 == domain2

    def test_different_domains_different_tokens(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("alice@company.com", FieldType.EMAIL)
        r2 = t.generate("alice@other.org", FieldType.EMAIL)
        domain1 = r1.split("@")[1]
        domain2 = r2.split("@")[1]
        assert domain1 != domain2


class TestEmailUsernameEntityLinking:
    def test_username_then_email(self):
        t = Tokenizer(seed="test")
        user_token = t.generate("jsmith", FieldType.USERNAME)
        email_token = t.generate("jsmith@company.com", FieldType.EMAIL)
        # The local part of the email should use the same USER token
        email_local = email_token.split("@")[0]
        assert email_local == user_token

    def test_email_then_username(self):
        t = Tokenizer(seed="test")
        email_token = t.generate("jsmith@company.com", FieldType.EMAIL)
        user_token = t.generate("jsmith", FieldType.USERNAME)
        email_local = email_token.split("@")[0]
        assert email_local == user_token


class TestUsername:
    def test_basic(self):
        t = Tokenizer(seed="test")
        assert t.generate("jsmith", FieldType.USERNAME).startswith("USER-")

    def test_two_different(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("jsmith", FieldType.USERNAME)
        r2 = t.generate("ajonas", FieldType.USERNAME)
        assert r1 != r2
        assert r1.startswith("USER-")
        assert r2.startswith("USER-")


class TestHostname:
    def test_basic(self):
        t = Tokenizer(seed="test")
        result = t.generate("sea-web-prod-01.corp.internal", FieldType.HOSTNAME)
        assert "HOST-" in result
        assert result.endswith(".corp.internal")

    def test_simple_hostname(self):
        t = Tokenizer(seed="test")
        result = t.generate("webserver.com", FieldType.HOSTNAME)
        assert "HOST-" in result
        assert result.endswith(".com")

    def test_single_segment(self):
        t = Tokenizer(seed="test")
        result = t.generate("localhost", FieldType.HOSTNAME)
        assert "HOST-" in result


class TestGroupName:
    def test_basic(self):
        t = Tokenizer(seed="test")
        assert t.generate("Finance-Leadership", FieldType.GROUP_NAME).startswith("GROUP-")

    def test_two_different(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("Finance", FieldType.GROUP_NAME)
        r2 = t.generate("Engineering", FieldType.GROUP_NAME)
        assert r1 != r2


class TestAppName:
    def test_basic(self):
        t = Tokenizer(seed="test")
        assert t.generate("Workday", FieldType.APP_NAME).startswith("APP-")

    def test_two_different(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("Workday", FieldType.APP_NAME)
        r2 = t.generate("Slack", FieldType.APP_NAME)
        assert r1 != r2


class TestPersonName:
    def test_basic(self):
        t = Tokenizer(seed="test")
        assert t.generate("John Smith", FieldType.PERSON_NAME).startswith("PERSON-")

    def test_two_different(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("John Smith", FieldType.PERSON_NAME)
        r2 = t.generate("Jane Doe", FieldType.PERSON_NAME)
        assert r1 != r2


class TestAccountId:
    def test_basic(self):
        t = Tokenizer(seed="test")
        assert t.generate("00u1abc2def3ghi4jkl", FieldType.ACCOUNT_ID).startswith("ACCT-")

    def test_two_different(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("00u1abc", FieldType.ACCOUNT_ID)
        r2 = t.generate("00u2xyz", FieldType.ACCOUNT_ID)
        assert r1 != r2


class TestEmailSubject:
    def test_basic(self):
        t = Tokenizer(seed="test")
        assert t.generate("Re: Q4 Layoffs", FieldType.EMAIL_SUBJECT).startswith("SUBJECT-")

    def test_two_different(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("Subject A", FieldType.EMAIL_SUBJECT)
        r2 = t.generate("Subject B", FieldType.EMAIL_SUBJECT)
        assert r1 != r2


class TestFilename:
    def test_preserves_extension(self):
        t = Tokenizer(seed="test")
        result = t.generate("acquisition-targets.xlsx", FieldType.FILENAME)
        assert result.startswith("FILE-")
        assert result.endswith(".xlsx")

    def test_no_extension(self):
        t = Tokenizer(seed="test")
        result = t.generate("Makefile", FieldType.FILENAME)
        assert result.startswith("FILE-")
        assert "." not in result

    def test_two_different(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("file1.txt", FieldType.FILENAME)
        r2 = t.generate("file2.txt", FieldType.FILENAME)
        assert r1 != r2


class TestDN:
    def test_basic(self):
        t = Tokenizer(seed="test")
        result = t.generate("CN=jsmith,OU=Finance,DC=corp", FieldType.DN)
        assert "CN=USER-" in result
        assert "OU=UNIT-" in result
        assert "DC=ORG-" in result

    def test_consistency(self):
        t = Tokenizer(seed="test")
        t.generate("jsmith", FieldType.USERNAME)
        result = t.generate("CN=jsmith,OU=Finance,DC=corp", FieldType.DN)
        # CN should reuse the same USER token
        assert "CN=USER-0001" in result


class TestUrlInternal:
    def test_basic(self):
        t = Tokenizer(seed="test")
        result = t.generate("https://vault.corp/v1/secret", FieldType.URL_INTERNAL)
        assert result.startswith("https://")
        assert "HOST-" in result
        assert "PATH-" in result

    def test_no_path(self):
        t = Tokenizer(seed="test")
        result = t.generate("https://vault.corp", FieldType.URL_INTERNAL)
        assert result.startswith("https://")
        assert "HOST-" in result

    def test_two_different(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("https://a.corp/p1", FieldType.URL_INTERNAL)
        r2 = t.generate("https://b.corp/p2", FieldType.URL_INTERNAL)
        assert r1 != r2


class TestDomainInternal:
    def test_basic(self):
        t = Tokenizer(seed="test")
        result = t.generate("corp.internal", FieldType.DOMAIN_INTERNAL)
        assert "ORG-" in result
        assert result.endswith(".internal")

    def test_two_different(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("corp.internal", FieldType.DOMAIN_INTERNAL)
        r2 = t.generate("other.internal", FieldType.DOMAIN_INTERNAL)
        assert r1 != r2


class TestMacAddress:
    def test_basic(self):
        t = Tokenizer(seed="test")
        result = t.generate("aa:bb:cc:dd:ee:ff", FieldType.MAC_ADDRESS)
        assert result.startswith("02:00:00:00:")
        parts = result.split(":")
        assert len(parts) == 6

    def test_two_different(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("aa:bb:cc:dd:ee:ff", FieldType.MAC_ADDRESS)
        r2 = t.generate("11:22:33:44:55:66", FieldType.MAC_ADDRESS)
        assert r1 != r2


class TestCertificateCN:
    def test_basic(self):
        t = Tokenizer(seed="test")
        assert t.generate("jsmith-laptop", FieldType.CERTIFICATE_CN).startswith("CERT-")

    def test_two_different(self):
        t = Tokenizer(seed="test")
        r1 = t.generate("cert1", FieldType.CERTIFICATE_CN)
        r2 = t.generate("cert2", FieldType.CERTIFICATE_CN)
        assert r1 != r2


class TestFilePath:
    def test_windows_path_with_username(self):
        t = Tokenizer(seed="test")
        result = t.generate(r"C:\Users\jsmith\Documents\report.docx", FieldType.FILE_PATH)
        assert result.startswith("C:\\")
        assert "USER-" in result
        assert result.endswith(".docx")

    def test_username_extraction(self):
        t = Tokenizer(seed="test")
        t.generate("jsmith", FieldType.USERNAME)
        result = t.generate(r"C:\Users\jsmith\Documents\report.docx", FieldType.FILE_PATH)
        # Should reuse the USER-0001 token from username
        assert "USER-0001" in result

    def test_unix_path(self):
        t = Tokenizer(seed="test")
        result = t.generate("/home/Users/jsmith/docs/file.txt", FieldType.FILE_PATH)
        assert "USER-" in result
        assert result.endswith(".txt")

    def test_two_different(self):
        t = Tokenizer(seed="test")
        r1 = t.generate(r"C:\Users\alice\file.txt", FieldType.FILE_PATH)
        r2 = t.generate(r"C:\Users\bob\file.txt", FieldType.FILE_PATH)
        assert r1 != r2


class TestUncPath:
    def test_basic(self):
        t = Tokenizer(seed="test")
        result = t.generate(r"\\fileserver\share\folder", FieldType.UNC_PATH)
        assert result.startswith("\\\\")
        assert "HOST-" in result
        assert "SHARE-" in result

    def test_hostname_extraction(self):
        t = Tokenizer(seed="test")
        t.generate("fileserver", FieldType.HOSTNAME)
        result = t.generate(r"\\fileserver\share\folder", FieldType.UNC_PATH)
        assert "HOST-0001" in result

    def test_two_different(self):
        t = Tokenizer(seed="test")
        r1 = t.generate(r"\\server1\share1", FieldType.UNC_PATH)
        r2 = t.generate(r"\\server2\share2", FieldType.UNC_PATH)
        assert r1 != r2


class TestPassthrough:
    def test_returns_unchanged(self):
        t = Tokenizer(seed="test")
        assert t.generate("10.0.0.1", FieldType.PASSTHROUGH) == "10.0.0.1"
        assert t.generate("anything", FieldType.PASSTHROUGH) == "anything"


class TestFreetext:
    def test_returns_unchanged(self):
        t = Tokenizer(seed="test")
        text = "Some freeform text with stuff"
        assert t.generate(text, FieldType.FREETEXT) == text
