from __future__ import annotations

import pytest

from core.loader import load_apk
from core.manifest import parse_manifest_xml, get_components
from core.ir import Component
from scanners.webview import WebViewScanner
from tests.helpers.fakes import FakeAPK


class DummyAnalysis:
    pass


def test_load_apk_valid_passthrough(monkeypatch):
    apk = object()
    dex = object()
    analysis = DummyAnalysis()

    def fake_analyze(path):
        return apk, dex, analysis

    monkeypatch.setattr("core.loader.AnalyzeAPK", fake_analyze)
    out_apk, out_dex, out_analysis = load_apk("fake.apk")
    assert out_apk is apk
    assert out_dex is dex
    assert out_analysis is analysis


def test_load_apk_malformed_raises(monkeypatch):
    def fake_analyze(path):
        raise ValueError("bad apk")

    monkeypatch.setattr("core.loader.AnalyzeAPK", fake_analyze)
    with pytest.raises(ValueError):
        load_apk("bad.apk")


def test_manifest_parsing_component_fields():
    xml = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test">
      <application>
        <activity android:name=".MainActivity">
          <intent-filter>
            <action android:name="android.intent.action.MAIN" />
            <category android:name="android.intent.category.LAUNCHER" />
          </intent-filter>
        </activity>
        <receiver android:name="com.test.InternalReceiver" android:exported="false" android:permission="com.test.PERM" />
        <provider android:name="com.test.NotesProvider"
            android:authorities="com.test.notes"
            android:grantUriPermissions="true"
            android:readPermission="com.test.READ"
            android:writePermission="com.test.WRITE" />
      </application>
    </manifest>
    """
    comps = parse_manifest_xml(xml)
    by_name = {c.name: c for c in comps}

    main = by_name[".MainActivity"]
    assert main.exported is True
    assert any("action:android.intent.action.MAIN" in f for f in main.intent_filters)

    recv = by_name["com.test.InternalReceiver"]
    assert recv.exported is False
    assert recv.permission == "com.test.PERM"

    provider = by_name["com.test.NotesProvider"]
    assert provider.authority == "com.test.notes"
    assert provider.notes == "grantUriPermissions=true; readPermission=com.test.READ; writePermission=com.test.WRITE"


def test_missing_manifest_returns_empty():
    apk = FakeAPK(manifest_xml=b"not xml", manifest_text=None)
    assert get_components(apk) == []


def test_multidex_context_accepts_list(make_ctx):
    components = [Component(name="com.test.MainActivity", type="activity", exported=True, permission=None, intent_filters=[])]
    ctx = make_ctx(components, methods=[], apk=FakeAPK(), max_depth=0)
    ctx.dex = [b"dex1", b"dex2"]
    scanner = WebViewScanner()
    findings = scanner.run(ctx)
    assert findings == []
