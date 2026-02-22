from __future__ import annotations

from core.models import Component
from scanners.crypto import CryptographyScanner
from tests.helpers.fakes import (
    FakeMethod,
    ins_invoke,
    ins_move_result,
    ins_const_string,
    ins_new_instance,
    ins_field,
    make_source,
)


def _run(scanner, make_ctx, methods):
    ctx = make_ctx([Component(name="com.test.Dummy", type="activity", exported=True, permission=None, intent_filters=[])], methods=methods)
    return scanner.run(ctx)


def test_ecb_and_weak_digest_rules(make_ctx):
    instructions = [
        ins_const_string("v0", "AES/ECB/PKCS5Padding"),
        ins_invoke("invoke-static", ["v0"], "Ljavax/crypto/Cipher;", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;"),
        ins_const_string("v1", "MD5"),
        ins_invoke("invoke-static", ["v1"], "Ljava/security/MessageDigest;", "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;"),
        ins_const_string("v2", "SHA-1"),
        ins_invoke("invoke-static", ["v2"], "Ljava/security/MessageDigest;", "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;"),
    ]
    method = FakeMethod("Lcom/test/CryptoUtil;", "encrypt", "()V", instructions)
    findings = _run(CryptographyScanner(), make_ctx, [method])
    ids = {f.id for f in findings}
    assert "AES_ECB_MODE" in ids
    assert "WEAK_DIGEST_MD5" in ids
    assert "WEAK_DIGEST_SHA1" in ids


def test_hardcoded_key_confirmed_and_heuristic(make_ctx):
    key = "MDEyMzQ1Njc4OWFiY2RlZg=="
    confirmed_instructions = [
        ins_const_string("v0", key),
        ins_invoke("invoke-static", ["v0", "v1"], "Landroid/util/Base64;", "decode", "(Ljava/lang/String;I)[B"),
        ins_move_result("v2"),
        ins_new_instance("v3", "Ljavax/crypto/spec/SecretKeySpec;"),
        ins_invoke("invoke-direct", ["v3", "v2", "v4"], "Ljavax/crypto/spec/SecretKeySpec;", "<init>", "([BLjava/lang/String;)V"),
    ]
    confirmed = FakeMethod("Lcom/test/CryptoUtil;", "initKey", "()V", confirmed_instructions, source=make_source(["SecretKeySpec"]))

    heuristic_instructions = [
        ins_const_string("v0", key),
        ins_const_string("v1", "AES/GCM/NoPadding"),
        ins_invoke("invoke-static", ["v1"], "Ljavax/crypto/Cipher;", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;"),
    ]
    heuristic = FakeMethod("Lcom/test/CryptoUtil;", "heuristicKey", "()V", heuristic_instructions)

    findings = _run(CryptographyScanner(), make_ctx, [confirmed, heuristic])
    ids = [f.id for f in findings if f.id == "HARDCODED_SECRET"]
    assert len(ids) >= 1


def test_hardcoded_crypto_iv_detection(make_ctx):
    class_name = "Lcom/test/CryptoUtil;"
    clinit_instructions = [
        ins_const_string("v0", "0123456789abcdef"),
        ins_invoke("invoke-virtual", ["v0"], "Ljava/lang/String;", "getBytes", "()[B"),
        ins_move_result("v1"),
        ins_field("sput-object", "v1", class_name, "IV", "[B"),
    ]
    clinit = FakeMethod(class_name, "<clinit>", "()V", clinit_instructions)

    use_instructions = [
        ins_field("sget-object", "v0", class_name, "IV", "[B"),
        ins_new_instance("v1", "Ljavax/crypto/spec/IvParameterSpec;"),
        ins_invoke("invoke-direct", ["v1", "v0"], "Ljavax/crypto/spec/IvParameterSpec;", "<init>", "([B)V"),
        ins_const_string("v2", "AES/CBC/PKCS5Padding"),
        ins_invoke("invoke-static", ["v2"], "Ljavax/crypto/Cipher;", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;"),
        ins_move_result("v3"),
        ins_invoke(
            "invoke-virtual",
            ["v3", "v4", "v5", "v1"],
            "Ljavax/crypto/Cipher;",
            "init",
            "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
        ),
    ]
    use = FakeMethod(class_name, "encrypt", "()V", use_instructions, source=make_source(["Cipher;->init"]))

    findings = _run(CryptographyScanner(), make_ctx, [clinit, use])
    assert any(f.id == "HARDCODED_SECRET" for f in findings)


def test_hardcoded_crypto_iv_detection_without_cbc(make_ctx):
    instructions = [
        ins_const_string("v0", "0123456789abcdef"),
        ins_invoke("invoke-virtual", ["v0"], "Ljava/lang/String;", "getBytes", "()[B"),
        ins_move_result("v1"),
        ins_new_instance("v2", "Ljavax/crypto/spec/IvParameterSpec;"),
        ins_invoke("invoke-direct", ["v2", "v1"], "Ljavax/crypto/spec/IvParameterSpec;", "<init>", "([B)V"),
    ]
    method = FakeMethod("Lcom/test/CryptoUtil;", "initIv", "()V", instructions)

    findings = _run(CryptographyScanner(), make_ctx, [method])
    assert any(f.id == "HARDCODED_SECRET" for f in findings)
