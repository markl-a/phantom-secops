"""Tests for the x-phantom metadata helper."""

from __future__ import annotations

import json

import pytest

from phantom_secops.mcp._xphantom import xphantom_metadata, validate_classification


def test_metadata_contains_namespaced_keys():
    md = xphantom_metadata("blue", ["read.log_files", "target.localhost_only"], read_only=True)
    assert md["x-phantom.classification"] == "blue"
    assert md["x-phantom.capabilities"] == ["read.log_files", "target.localhost_only"]
    assert md["x-phantom.read_only"] is True


def test_classification_validation_rejects_unknown():
    with pytest.raises(ValueError, match="classification"):
        xphantom_metadata("purple", [], read_only=True)


def test_classification_ordering():
    assert validate_classification("internal") < validate_classification("blue")
    assert validate_classification("blue") < validate_classification("red")


def test_capabilities_must_be_list_of_strings():
    with pytest.raises(TypeError):
        xphantom_metadata("red", "not_a_list", read_only=False)
    with pytest.raises(TypeError):
        xphantom_metadata("red", [123], read_only=False)


def test_metadata_is_json_serializable():
    md = xphantom_metadata("internal", ["read.config.local"], read_only=True)
    s = json.dumps(md)
    assert "x-phantom.classification" in s
