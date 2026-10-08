import base64
import hashlib
import json
import os
import struct
import time
from io import BytesIO

import pytest
from Crypto.Cipher import AES

os.environ.setdefault("WECHAT_TOKEN", "test-token")
os.environ.setdefault("WECHAT_ENCODING_AES_KEY", "a" * 43)
os.environ.setdefault("CorpTD", "test-corpid")
os.environ.setdefault("Secret", "test-secret")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-llm-key")
os.environ.setdefault("ANTHROPIC_BASE_URL", "https://test-llm.example.com")
os.environ.setdefault("ANTHROPIC_MODEL", "test-model")

import config  # noqa: E402  (env vars must be set before import)
import server  # noqa: E402
from src import llm, message, routes, storage, task, upload, wechat_api  # noqa: E402


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = 32 - (len(data) % 32)
    return data + bytes([pad_len]) * pad_len


def _aes_encrypt(encoding_aes_key: str, plaintext: str) -> str:
    # 与微信一致的封装：16字节随机数 | 4字节大端长度 | 内容 | corpid，再 PKCS7 填充后 AES-CBC 加密
    key = base64.b64decode(encoding_aes_key + "=")
    iv = key[:16]
    random_bytes = os.urandom(16)
    content = plaintext.encode("utf-8")
    packed = random_bytes + struct.pack(">I", len(content)) + content + server.CORP_ID.encode("utf-8")
    padded = _pkcs7_pad(packed)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(cipher.encrypt(padded)).decode("utf-8")


def _sign(token: str, timestamp: str, nonce: str, echo_or_encrypt: str) -> str:
    parts = sorted([token, timestamp, nonce, echo_or_encrypt])
    return hashlib.sha1("".join(parts).encode("utf-8")).hexdigest()


def _build_callback_xml(encrypt: str) -> bytes:
    return f"<xml><ToUserName><![CDATA[wwCorp]]></ToUserName><Encrypt><![CDATA[{encrypt}]]></Encrypt></xml>".encode(
        "utf-8"
    )


@pytest.fixture
def client():
    server.app.config.update(TESTING=True)
    return server.app.test_client()


@pytest.fixture(autouse=True)
def reset_state():
    # 每个测试前重置 token 缓存与游标存储，避免测试间相互影响
    storage.token_cache["access_token"] = None
    storage.token_cache["expires_at"] = 0.0
    storage.cursor_store.clear()
    storage.used_upload_tokens.clear()
    yield


class TestSignatureCheck:
    def test_valid_signature_passes(self):
        sig = _sign("tok", "123", "abc", "hello")
        assert routes.crypto.check_signature("tok", "123", "abc", "hello", sig) is True

    def test_invalid_signature_fails(self):
        assert routes.crypto.check_signature("tok", "123", "abc", "hello", "deadbeef") is False


class TestAesRoundTrip:
    def test_encrypt_then_decrypt_returns_original(self):
        encrypt = _aes_encrypt(server.ENCODING_AES_KEY, "hello world")
        assert routes.crypto.aes_decrypt(server.ENCODING_AES_KEY, encrypt) == "hello world"


class TestServeFile:
    def test_serves_existing_file(self, client, mocker, tmp_path):
        mocker.patch("src.routes.FILES_DIR", str(tmp_path))
        (tmp_path / "a.pdf").write_bytes(b"pdf-content")

        resp = client.get("/files/a.pdf")

        assert resp.status_code == 200
        assert resp.data == b"pdf-content"

    def test_rejects_path_traversal(self, client, mocker, tmp_path):
        mocker.patch("src.routes.FILES_DIR", str(tmp_path))
        (tmp_path / "a.pdf").write_bytes(b"pdf-content")

        resp = client.get("/files/..%2f..%2fserver.py")

        assert resp.status_code in (400, 404)

    def test_returns_404_for_missing_file(self, client, mocker, tmp_path):
        mocker.patch("src.routes.FILES_DIR", str(tmp_path))

        resp = client.get("/files/missing.pdf")

        assert resp.status_code == 404


class TestUploadToken:
    def test_load_valid_token_returns_data(self):
        token = upload.make_upload_token("wmUser1", "wkxxxxxxx")

        result = upload.load_upload_token(token)

        assert result["valid"] is True
        assert result["external_userid"] == "wmUser1"
        assert result["open_kfid"] == "wkxxxxxxx"

    def test_load_tampered_token_is_invalid(self):
        token = upload.make_upload_token("wmUser1", "wkxxxxxxx")

        result = upload.load_upload_token(token + "tampered")

        assert result["valid"] is False

    def test_load_expired_token_is_invalid(self, mocker):
        mocker.patch.object(config, "UPLOAD_TOKEN_MAX_AGE", -1)
        token = upload.make_upload_token("wmUser1", "wkxxxxxxx")

        result = upload.load_upload_token(token)

        assert result["valid"] is False
        assert "过期" in result["error"]

    def test_used_token_is_rejected(self):
        token = upload.make_upload_token("wmUser1", "wkxxxxxxx")
        upload.mark_upload_token_used(token)

        result = upload.load_upload_token(token)

        assert result["valid"] is False
        assert "已被使用" in result["error"]


class TestSafeUploadFilename:
    def test_keeps_chinese_characters(self):
        assert upload.safe_upload_filename("尽调报告.pdf") == "尽调报告.pdf"

    def test_strips_path_separators(self):
        assert "/" not in upload.safe_upload_filename("../../etc/passwd")
        assert "\\" not in upload.safe_upload_filename("..\\..\\windows\\system32\\evil.exe")

    def test_empty_name_falls_back(self):
        assert upload.safe_upload_filename("...") == "unnamed"


class TestUploadEndpoint:
    def test_upload_form_rejects_invalid_token(self, client):
        resp = client.get("/upload/not-a-real-token")

        assert resp.status_code == 403

    def test_upload_form_accepts_valid_token(self, client):
        token = upload.make_upload_token("wmUser1", "wkxxxxxxx")

        resp = client.get(f"/upload/{token}")

        assert resp.status_code == 200
        assert "上传" in resp.data.decode("utf-8")

    def test_upload_file_saves_and_notifies(self, client, mocker, tmp_path):
        mocker.patch.object(config, "UPLOADS_DIR", str(tmp_path))
        mock_send = mocker.patch("src.wechat_api.send_text_msg")
        token = upload.make_upload_token("wmUser1", "wkxxxxxxx")

        resp = client.post(
            f"/upload/{token}",
            data={"file": (BytesIO(b"file-bytes"), "report.pdf")},
            content_type="multipart/form-data",
        )

        assert resp.status_code == 200
        saved_files = list(tmp_path.iterdir())
        assert len(saved_files) == 1
        assert saved_files[0].name.startswith("report_")
        mock_send.assert_called_once()
        _, args, _ = mock_send.mock_calls[0]
        assert args[0] == "wmUser1"
        assert args[1] == "wkxxxxxxx"

    def test_upload_file_rejects_reused_token(self, client, mocker, tmp_path):
        mocker.patch.object(config, "UPLOADS_DIR", str(tmp_path))
        mocker.patch("src.wechat_api.send_text_msg")
        token = upload.make_upload_token("wmUser1", "wkxxxxxxx")

        client.post(
            f"/upload/{token}",
            data={"file": (BytesIO(b"file-bytes"), "report.pdf")},
            content_type="multipart/form-data",
        )
        resp2 = client.post(
            f"/upload/{token}",
            data={"file": (BytesIO(b"file-bytes-2"), "report2.pdf")},
            content_type="multipart/form-data",
        )

        assert resp2.status_code == 403

    def test_upload_file_without_file_returns_400(self, client):
        token = upload.make_upload_token("wmUser1", "wkxxxxxxx")

        resp = client.post(f"/upload/{token}", data={}, content_type="multipart/form-data")

        assert resp.status_code == 400

    def test_upload_file_too_large_returns_413(self, client):
        original = server.app.config["MAX_CONTENT_LENGTH"]
        server.app.config["MAX_CONTENT_LENGTH"] = 10
        try:
            token = upload.make_upload_token("wmUser1", "wkxxxxxxx")

            resp = client.post(
                f"/upload/{token}",
                data={"file": (BytesIO(b"x" * 1000), "big.bin")},
                content_type="multipart/form-data",
            )

            assert resp.status_code == 413
        finally:
            server.app.config["MAX_CONTENT_LENGTH"] = original


class TestVerifyEndpoint:
    def test_url_verification_returns_decrypted_echostr(self, client):
        echostr = _aes_encrypt(server.ENCODING_AES_KEY, "echo-plaintext")
        sig = _sign(server.TOKEN, "1000", "nonce1", echostr)

        resp = client.get(
            "/wechat/callback",
            query_string={"msg_signature": sig, "timestamp": "1000", "nonce": "nonce1", "echostr": echostr},
        )

        assert resp.status_code == 200
        assert resp.data.decode("utf-8") == "echo-plaintext"

    def test_url_verification_rejects_bad_signature(self, client):
        echostr = _aes_encrypt(server.ENCODING_AES_KEY, "echo-plaintext")

        resp = client.get(
            "/wechat/callback",
            query_string={"msg_signature": "bad", "timestamp": "1000", "nonce": "nonce1", "echostr": echostr},
        )

        assert resp.status_code == 403


class TestReceiveEndpoint:
    def _post_event(self, client, event_xml: str):
        encrypt = _aes_encrypt(server.ENCODING_AES_KEY, event_xml)
        sig = _sign(server.TOKEN, "2000", "nonce2", encrypt)
        body = _build_callback_xml(encrypt)
        return client.post(
            "/wechat/callback",
            query_string={"msg_signature": sig, "timestamp": "2000", "nonce": "nonce2"},
            data=body,
            content_type="application/xml",
        )

    def test_rejects_bad_signature(self, client):
        encrypt = _aes_encrypt(server.ENCODING_AES_KEY, "<xml></xml>")
        body = _build_callback_xml(encrypt)

        resp = client.post(
            "/wechat/callback",
            query_string={"msg_signature": "bad", "timestamp": "2000", "nonce": "nonce2"},
            data=body,
            content_type="application/xml",
        )

        assert resp.status_code == 403

    def test_new_customer_message_triggers_sync_and_reply(self, client, mocker):
        event_xml = (
            "<xml>"
            "<ToUserName><![CDATA[ww12345678910]]></ToUserName>"
            "<CreateTime>1348831860</CreateTime>"
            "<MsgType><![CDATA[event]]></MsgType>"
            "<Event><![CDATA[kf_msg_or_event]]></Event>"
            "<Token><![CDATA[kftoken123]]></Token>"
            "<OpenKfId><![CDATA[wkxxxxxxx]]></OpenKfId>"
            "</xml>"
        )

        mock_sync = mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "from_msgid_1",
                    "open_kfid": "wkxxxxxxx",
                    "external_userid": "wmExternalUser1",
                    "send_time": 1615478585,
                    "origin": 3,
                    "msgtype": "text",
                    "text": {"content": "任意消息"},
                }
            ],
        )
        mock_send = mocker.patch(
            "src.wechat_api.send_text_msg", return_value={"errcode": 0, "errmsg": "ok", "msgid": "m1"}
        )
        mock_llm = mocker.patch("src.llm.reply", return_value="收到，请问有什么可以帮您？")

        resp = self._post_event(client, event_xml)

        assert resp.status_code == 200
        assert resp.data.decode("utf-8") == "success"
        mock_sync.assert_called_once_with("kftoken123", "wkxxxxxxx")
        mock_llm.assert_called_once_with("任意消息")
        mock_send.assert_called_once_with("wmExternalUser1", "wkxxxxxxx", "收到，请问有什么可以帮您？")

    def test_system_pushed_message_does_not_trigger_reply(self, client, mocker):
        event_xml = (
            "<xml>"
            "<MsgType><![CDATA[event]]></MsgType>"
            "<Event><![CDATA[kf_msg_or_event]]></Event>"
            "<Token><![CDATA[kftoken123]]></Token>"
            "<OpenKfId><![CDATA[wkxxxxxxx]]></OpenKfId>"
            "</xml>"
        )

        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "from_msgid_2",
                    "open_kfid": "wkxxxxxxx",
                    "external_userid": "wmExternalUser1",
                    "send_time": 1615478585,
                    "origin": 4,
                    "msgtype": "event",
                }
            ],
        )
        mock_send = mocker.patch("src.wechat_api.send_text_msg")

        resp = self._post_event(client, event_xml)

        assert resp.status_code == 200
        mock_send.assert_not_called()

    def test_non_kf_event_is_ignored(self, client, mocker):
        event_xml = "<xml><MsgType><![CDATA[event]]></MsgType><Event><![CDATA[enter_session]]></Event></xml>"
        mock_sync = mocker.patch("src.wechat_api.sync_msg")

        resp = self._post_event(client, event_xml)

        assert resp.status_code == 200
        mock_sync.assert_not_called()


class TestAccessToken:
    def test_fetches_and_caches_token(self, mocker):
        mock_get = mocker.patch("src.wechat_api.requests.get")
        mock_get.return_value.json.return_value = {"errcode": 0, "access_token": "tok1", "expires_in": 7200}

        token = wechat_api.get_access_token()
        token_again = wechat_api.get_access_token()

        assert token == "tok1"
        assert token_again == "tok1"
        mock_get.assert_called_once()  # 第二次应直接命中缓存

    def test_refetches_when_expired(self, mocker):
        mock_get = mocker.patch("src.wechat_api.requests.get")
        mock_get.return_value.json.return_value = {"errcode": 0, "access_token": "tok1", "expires_in": 7200}

        wechat_api.get_access_token()
        storage.token_cache["expires_at"] = time.time() - 1  # 强制标记为已过期
        wechat_api.get_access_token()

        assert mock_get.call_count == 2

    def test_raises_on_error(self, mocker):
        mock_get = mocker.patch("src.wechat_api.requests.get")
        mock_get.return_value.json.return_value = {"errcode": 40001, "errmsg": "invalid credential"}

        with pytest.raises(RuntimeError):
            wechat_api.get_access_token()


class TestSyncMsg:
    def test_paginates_until_has_more_is_false(self, mocker):
        mocker.patch("src.wechat_api.get_access_token", return_value="tok")
        mock_post = mocker.patch("src.wechat_api.requests.post")
        mock_post.return_value.json.side_effect = [
            {"errcode": 0, "msg_list": [{"msgid": "1"}], "next_cursor": "c1", "has_more": 1},
            {"errcode": 0, "msg_list": [{"msgid": "2"}], "next_cursor": "c2", "has_more": 0},
        ]
        mocker.patch("src.wechat_api.storage.save_cursors")  # mock 掉文件保存

        msgs = wechat_api.sync_msg("kftoken", "wkxxxxxxx")

        assert [m["msgid"] for m in msgs] == ["1", "2"]
        assert storage.cursor_store["wkxxxxxxx"] == "c2"
        assert mock_post.call_count == 2

    def test_raises_on_error(self, mocker):
        mocker.patch("src.wechat_api.get_access_token", return_value="tok")
        mock_post = mocker.patch("src.wechat_api.requests.post")
        mock_post.return_value.json.return_value = {"errcode": 60011, "errmsg": "not a valid openkfid"}

        with pytest.raises(RuntimeError):
            wechat_api.sync_msg("kftoken", "wkxxxxxxx")

    def test_saves_cursor_after_each_page(self, mocker):
        mocker.patch("src.wechat_api.get_access_token", return_value="tok")
        mock_post = mocker.patch("src.wechat_api.requests.post")
        mock_post.return_value.json.side_effect = [
            {"errcode": 0, "msg_list": [], "next_cursor": "c1", "has_more": 1},
            {"errcode": 0, "msg_list": [], "next_cursor": "c2", "has_more": 0},
        ]
        mock_save = mocker.patch("src.wechat_api.storage.save_cursors")

        wechat_api.sync_msg("kftoken", "wkxxxxxxx")

        assert mock_save.call_count == 2  # 每次更新游标后都调用


class TestCursorPersistence:
    def test_load_cursors_from_file(self, mocker, tmp_path):
        cursor_file = tmp_path / "cursors.json"
        cursor_file.write_text('{"wkAAAAA": "cursor123"}')
        mocker.patch("src.storage.CURSOR_FILE", str(cursor_file))

        storage.load_cursors()

        assert storage.cursor_store == {"wkAAAAA": "cursor123"}

    def test_load_cursors_handles_missing_file(self, mocker, tmp_path):
        mocker.patch("src.storage.CURSOR_FILE", str(tmp_path / "nonexistent.json"))

        storage.load_cursors()  # 不应抛异常

        assert storage.cursor_store == {}

    def test_save_cursors_writes_to_file(self, mocker, tmp_path):
        cursor_file = tmp_path / "cursors.json"
        mocker.patch("src.storage.CURSOR_FILE", str(cursor_file))
        storage.cursor_store.clear()
        storage.cursor_store.update({"wkBBBBB": "cursor456"})

        storage.save_cursors()

        assert cursor_file.exists()
        assert json.loads(cursor_file.read_text()) == {"wkBBBBB": "cursor456"}


class TestSendTextMsg:
    def test_sends_expected_payload(self, mocker):
        mocker.patch("src.wechat_api.get_access_token", return_value="tok")
        mock_post = mocker.patch("src.wechat_api.requests.post")
        mock_post.return_value.json.return_value = {"errcode": 0, "errmsg": "ok", "msgid": "m1"}

        result = wechat_api.send_text_msg("wmUser1", "wkxxxxxxx", "成功接收消息")

        assert result["msgid"] == "m1"
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["touser"] == "wmUser1"
        assert kwargs["json"]["open_kfid"] == "wkxxxxxxx"
        assert kwargs["json"]["text"]["content"] == "成功接收消息"

    def test_raises_on_error(self, mocker):
        mocker.patch("src.wechat_api.get_access_token", return_value="tok")
        mock_post = mocker.patch("src.wechat_api.requests.post")
        mock_post.return_value.json.return_value = {"errcode": 95003, "errmsg": "not allow to send message"}

        with pytest.raises(RuntimeError):
            wechat_api.send_text_msg("wmUser1", "wkxxxxxxx", "成功接收消息")


class TestLlmReply:
    def test_sends_expected_payload_and_returns_content(self, mocker):
        mock_post = mocker.patch("src.llm.requests.post")
        mock_post.return_value.json.return_value = {
            "choices": [{"message": {"content": "你好，请问有什么可以帮您？"}}]
        }

        result = llm.reply("你好")

        assert result == "你好，请问有什么可以帮您？"
        args, kwargs = mock_post.call_args
        assert args[0].endswith("/v1/chat/completions")
        assert kwargs["headers"]["Authorization"] == f"Bearer {os.environ['ANTHROPIC_API_KEY']}"
        assert kwargs["json"]["model"] == os.environ["ANTHROPIC_MODEL"]
        assert kwargs["json"]["messages"][0] == {"role": "system", "content": config.LLM_SYSTEM_PROMPT}
        assert kwargs["json"]["messages"][1] == {"role": "user", "content": "你好"}

    def test_raises_when_response_has_no_choices(self, mocker):
        mock_post = mocker.patch("src.llm.requests.post")
        mock_post.return_value.json.return_value = {"error": {"message": "invalid api key"}}

        with pytest.raises(RuntimeError):
            llm.reply("你好")


class TestDownloadMedia:
    def test_download_success(self, mocker, tmp_path):
        mocker.patch("src.wechat_api.get_access_token", return_value="tok")
        mock_get = mocker.patch("src.wechat_api.requests.get")
        mock_resp = mock_get.return_value
        mock_resp.headers = {
            "Content-Type": "image/png",
            "Content-Disposition": 'attachment; filename="test.png"',
        }
        mock_resp.iter_content.return_value = [b"fake", b"image", b"data"]

        result = wechat_api.download_media("media123", save_dir=str(tmp_path))

        assert result["success"] is True
        assert result["filename"] == "test.png"
        assert result["size"] == 13
        assert os.path.exists(result["filepath"])

    def test_download_api_error(self, mocker):
        mocker.patch("src.wechat_api.get_access_token", return_value="tok")
        mock_get = mocker.patch("src.wechat_api.requests.get")
        mock_resp = mock_get.return_value
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.json.return_value = {"errcode": 40007, "errmsg": "invalid media_id"}

        result = wechat_api.download_media("bad_media")

        assert result["success"] is False
        assert "invalid media_id" in result["error"]

    def test_download_without_filename(self, mocker, tmp_path):
        mocker.patch("src.wechat_api.get_access_token", return_value="tok")
        mock_get = mocker.patch("src.wechat_api.requests.get")
        mock_resp = mock_get.return_value
        mock_resp.headers = {"Content-Type": "application/octet-stream"}
        mock_resp.iter_content.return_value = [b"data"]

        result = wechat_api.download_media("media_long_id_12345", save_dir=str(tmp_path))

        assert result["success"] is True
        assert result["filename"].endswith(".amr")


class TestUploadAndSendFile:
    def test_upload_temp_media_returns_media_id(self, mocker, tmp_path):
        mocker.patch("src.wechat_api.get_access_token", return_value="tok")
        sample_file = tmp_path / "sample.pdf"
        sample_file.write_bytes(b"fake pdf content")
        mock_post = mocker.patch("src.wechat_api.requests.post")
        mock_post.return_value.json.return_value = {"errcode": 0, "media_id": "media_abc"}

        media_id = wechat_api.upload_temp_media(str(sample_file))

        assert media_id == "media_abc"
        _, kwargs = mock_post.call_args
        assert kwargs["params"]["type"] == "file"

    def test_upload_temp_media_raises_on_error(self, mocker, tmp_path):
        mocker.patch("src.wechat_api.get_access_token", return_value="tok")
        sample_file = tmp_path / "sample.pdf"
        sample_file.write_bytes(b"fake pdf content")
        mock_post = mocker.patch("src.wechat_api.requests.post")
        mock_post.return_value.json.return_value = {"errcode": 40004, "errmsg": "invalid media type"}

        with pytest.raises(RuntimeError):
            wechat_api.upload_temp_media(str(sample_file))

    def test_send_link_msg_sends_expected_payload(self, mocker):
        mocker.patch("src.wechat_api.get_access_token", return_value="tok")
        mock_post = mocker.patch("src.wechat_api.requests.post")
        mock_post.return_value.json.return_value = {"errcode": 0, "errmsg": "ok", "msgid": "m1"}

        result = wechat_api.send_link_msg(
            "wmUser1", "wkxxxxxxx", "标题", "描述", "https://example.com/files/a.pdf", "thumb_abc"
        )

        assert result["msgid"] == "m1"
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["msgtype"] == "link"
        assert kwargs["json"]["link"]["url"] == "https://example.com/files/a.pdf"
        assert kwargs["json"]["link"]["thumb_media_id"] == "thumb_abc"

    def test_send_link_msg_raises_on_error(self, mocker):
        mocker.patch("src.wechat_api.get_access_token", return_value="tok")
        mock_post = mocker.patch("src.wechat_api.requests.post")
        mock_post.return_value.json.return_value = {"errcode": 95003, "errmsg": "not allow to send message"}

        with pytest.raises(RuntimeError):
            wechat_api.send_link_msg(
                "wmUser1", "wkxxxxxxx", "标题", "描述", "https://example.com/files/a.pdf", "thumb_abc"
            )


class TestFileMessageHandling:
    def test_file_message_triggers_download_and_reply(self, mocker, tmp_path):
        mocker.patch("src.wechat_api.get_access_token", return_value="tok")
        mock_sync = mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "file_msg_1",
                    "open_kfid": "wkxxxxxxx",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "file",
                    "file": {"media_id": "media123"},
                }
            ],
        )
        mock_download = mocker.patch(
            "src.wechat_api.download_media",
            return_value={"success": True, "filepath": str(tmp_path / "test.pdf"), "filename": "test.pdf", "size": 2048000},
        )
        mock_send = mocker.patch("src.wechat_api.send_text_msg", return_value={"errcode": 0, "msgid": "m1"})

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        mock_download.assert_called_once_with("media123")
        mock_send.assert_called_once()
        _, args, _ = mock_send.mock_calls[0]
        assert "已成功接收test.pdf文件" in args[2]
        assert "1.95MB" in args[2]

    def test_image_message_triggers_download(self, mocker):
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "img_msg_1",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "image",
                    "image": {"media_id": "img123"},
                }
            ],
        )
        mock_download = mocker.patch(
            "src.wechat_api.download_media",
            return_value={"success": True, "filepath": "/tmp/pic.jpg", "filename": "pic.jpg", "size": 512000},
        )
        mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        mock_download.assert_called_once_with("img123")

    def test_download_failure_replies_error(self, mocker):
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "file_msg_2",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "file",
                    "file": {"media_id": "bad_media"},
                }
            ],
        )
        mocker.patch("src.wechat_api.download_media", return_value={"success": False, "error": "invalid media_id"})
        mock_send = mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        _, args, _ = mock_send.mock_calls[0]
        assert "文件接收失败" in args[2]
        assert "invalid media_id" in args[2]

    def test_voice_message_triggers_download_and_fixed_reply(self, mocker, tmp_path):
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "voice_msg_1",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "voice",
                    "voice": {"media_id": "voice123"},
                }
            ],
        )
        mock_download = mocker.patch(
            "src.wechat_api.download_media",
            return_value={"success": True, "filepath": str(tmp_path / "test.amr"), "filename": "test.amr", "size": 20480},
        )
        mock_send = mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        mock_download.assert_called_once_with("voice123")
        _, args, _ = mock_send.mock_calls[0]
        assert args[2] == "已接收语音消息"

    def test_voice_download_failure_replies_error(self, mocker):
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "voice_msg_2",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "voice",
                    "voice": {"media_id": "bad_voice"},
                }
            ],
        )
        mocker.patch("src.wechat_api.download_media", return_value={"success": False, "error": "invalid media_id"})
        mock_send = mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        _, args, _ = mock_send.mock_calls[0]
        assert "文件接收失败" in args[2]

    def test_generic_text_message_replies_with_llm_output(self, mocker):
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "txt_generic_1",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "text",
                    "text": {"content": "你好"},
                }
            ],
        )
        mock_llm = mocker.patch("src.llm.reply", return_value="您好，请问有什么可以帮您？")
        mock_send = mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        mock_llm.assert_called_once_with("你好")
        _, args, _ = mock_send.mock_calls[0]
        assert args[2] == "您好，请问有什么可以帮您？"

    def test_generic_text_message_falls_back_when_llm_fails(self, mocker):
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "txt_generic_2",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "text",
                    "text": {"content": "你好"},
                }
            ],
        )
        mocker.patch("src.llm.reply", side_effect=RuntimeError("llm reply failed"))
        mock_send = mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        _, args, _ = mock_send.mock_calls[0]
        assert args[2] == "成功接收消息"

    def test_trigger_keyword_pushes_link_and_sends_no_text_reply(self, mocker):
        mocker.patch.object(config, "PUBLIC_BASE_URL", "https://example.com")
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "txt_trigger_1",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "text",
                    "text": {"content": config.PUSH_FILE_TRIGGER},
                }
            ],
        )
        mock_upload = mocker.patch("src.wechat_api.upload_temp_media", return_value="thumb_media_1")
        mock_send_link = mocker.patch("src.wechat_api.send_link_msg", return_value={"errcode": 0, "msgid": "m1"})
        mock_send_text = mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        mock_upload.assert_called_once_with(config.PUSH_LINK_THUMB_PATH, media_type="image")
        expected_filename = os.path.basename(config.PUSH_FILE_PATH)
        mock_send_link.assert_called_once_with(
            "wmUser1",
            "wkxxxxxxx",
            config.PUSH_LINK_TITLE,
            config.PUSH_LINK_DESC,
            f"https://example.com/files/{expected_filename}",
            "thumb_media_1",
        )
        mock_send_text.assert_not_called()

    def test_trigger_keyword_push_failure_replies_error_text(self, mocker):
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "txt_trigger_2",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "text",
                    "text": {"content": config.PUSH_FILE_TRIGGER},
                }
            ],
        )
        mocker.patch("src.wechat_api.upload_temp_media", side_effect=RuntimeError("media upload failed: boom"))
        mock_send_text = mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        _, args, _ = mock_send_text.mock_calls[0]
        assert "文件推送失败" in args[2]

    def test_non_trigger_text_message_does_not_push_file(self, mocker):
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "txt_msg_2",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "text",
                    "text": {"content": "随便说点什么"},
                }
            ],
        )
        mock_upload = mocker.patch("src.wechat_api.upload_temp_media")
        mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        mock_upload.assert_not_called()

    def test_upload_trigger_keyword_pushes_upload_link(self, mocker):
        mocker.patch.object(config, "PUBLIC_BASE_URL", "https://example.com")
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "txt_upload_trigger_1",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "text",
                    "text": {"content": config.UPLOAD_TRIGGER},
                }
            ],
        )
        mocker.patch("src.wechat_api.upload_temp_media", return_value="thumb_media_2")
        mock_make_token = mocker.patch("src.upload.make_upload_token", return_value="tok123")
        mock_send_link = mocker.patch("src.wechat_api.send_link_msg", return_value={"errcode": 0, "msgid": "m1"})
        mock_send_text = mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        mock_make_token.assert_called_once_with("wmUser1", "wkxxxxxxx")
        mock_send_link.assert_called_once_with(
            "wmUser1",
            "wkxxxxxxx",
            config.UPLOAD_LINK_TITLE,
            config.UPLOAD_LINK_DESC,
            "https://example.com/upload/tok123",
            "thumb_media_2",
        )
        mock_send_text.assert_not_called()

    def test_upload_trigger_failure_replies_error_text(self, mocker):
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "txt_upload_trigger_2",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "text",
                    "text": {"content": config.UPLOAD_TRIGGER},
                }
            ],
        )
        mocker.patch("src.wechat_api.upload_temp_media", side_effect=RuntimeError("media upload failed: boom"))
        mock_send_text = mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        _, args, _ = mock_send_text.mock_calls[0]
        assert "上传链接生成失败" in args[2]

    def test_reply_delay_sleeps_before_sending(self, mocker):
        mocker.patch.object(config, "REPLY_DELAY_SECONDS", 5)
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "txt_msg_delay_1",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "text",
                    "text": {"content": "hello"},
                }
            ],
        )
        mock_sleep = mocker.patch("src.message.time.sleep")
        mock_send = mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        mock_sleep.assert_called_once_with(5)
        mock_send.assert_called_once()

    def test_no_delay_when_zero(self, mocker):
        mocker.patch.object(config, "REPLY_DELAY_SECONDS", 0)
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "txt_msg_delay_2",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "text",
                    "text": {"content": "hello"},
                }
            ],
        )
        mock_sleep = mocker.patch("src.message.time.sleep")
        mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        mock_sleep.assert_not_called()

    def test_text_message_does_not_download(self, mocker):
        mocker.patch(
            "src.wechat_api.sync_msg",
            return_value=[
                {
                    "msgid": "txt_msg_1",
                    "external_userid": "wmUser1",
                    "origin": 3,
                    "msgtype": "text",
                    "text": {"content": "hello"},
                }
            ],
        )
        mock_download = mocker.patch("src.wechat_api.download_media")
        mocker.patch("src.wechat_api.send_text_msg")

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        mock_download.assert_not_called()


class TestTaskFlow:
    def setup_method(self):
        storage.tasks_by_user.clear()

    def _sync_msg_with(self, content):
        return [
            {
                "msgid": "task_msg_1",
                "external_userid": "wmUser1",
                "origin": 3,
                "msgtype": "text",
                "text": {"content": content},
            }
        ]

    def test_task_trigger_creates_task_and_pushes_progress_then_result(self, mocker):
        mocker.patch("src.wechat_api.sync_msg", return_value=self._sync_msg_with("开始任务：查询阿里巴巴公司"))
        mock_sleep = mocker.patch("src.task.time.sleep")
        mock_send = mocker.patch("src.wechat_api.send_text_msg", return_value={"errcode": 0, "msgid": "m1"})

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        sent_texts = [call.args[2] for call in mock_send.mock_calls]
        assert sent_texts == [
            "收到任务",
            "正在检索本地信息...",
            "正在处理信息...",
            "信息不足，正在联网搜索信息作为补充...",
            "信息收集完毕，开始汇总...",
            "查询阿里巴巴公司任务已完成",
        ]
        # 5 条进度间隔 + 1 次任务处理延迟
        assert mock_sleep.call_count == 6
        mock_sleep.assert_any_call(config.TASK_PROCESS_DELAY_SECONDS)

        tasks = storage.tasks_by_user["wmUser1"]
        assert len(tasks) == 1
        assert tasks[0]["status"] == "pushed"
        assert tasks[0]["content"] == "查询阿里巴巴公司"

    def test_task_marked_push_failed_when_result_push_fails(self, mocker):
        mocker.patch("src.wechat_api.sync_msg", return_value=self._sync_msg_with("开始任务：查询阿里巴巴公司"))
        mocker.patch("src.task.time.sleep")
        # 前 5 条进度消息成功，最后一条结果推送失败（模拟窗口关闭/配额耗尽）
        mocker.patch(
            "src.wechat_api.send_text_msg",
            side_effect=[None, None, None, None, None, RuntimeError("send_msg failed: window closed")],
        )

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        tasks = storage.tasks_by_user["wmUser1"]
        assert tasks[0]["status"] == "push_failed"

    def test_next_message_auto_pushes_failed_task_result(self, mocker):
        mocker.patch("src.task.time.sleep")
        created = task.create_task("wmUser1", "查询阿里巴巴公司")
        created["status"] = "push_failed"

        mocker.patch("src.wechat_api.sync_msg", return_value=self._sync_msg_with("你好"))
        mock_send = mocker.patch("src.wechat_api.send_text_msg", return_value={"errcode": 0, "msgid": "m1"})

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        sent_texts = [call.args[2] for call in mock_send.mock_calls]
        assert "查询阿里巴巴公司任务已完成" in sent_texts
        assert created["status"] == "pushed"

    def test_next_message_retry_push_failure_keeps_status(self, mocker):
        mocker.patch("src.task.time.sleep")
        created = task.create_task("wmUser1", "查询阿里巴巴公司")
        created["status"] = "push_failed"

        mocker.patch("src.wechat_api.sync_msg", return_value=self._sync_msg_with("你好"))
        mocker.patch("src.wechat_api.send_text_msg", side_effect=RuntimeError("send_msg failed: window closed"))

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        assert created["status"] == "push_failed"

    def test_pushed_task_is_not_pushed_again(self, mocker):
        mocker.patch("src.task.time.sleep")
        created = task.create_task("wmUser1", "查询阿里巴巴公司")
        created["status"] = "pushed"

        mocker.patch("src.wechat_api.sync_msg", return_value=self._sync_msg_with("你好"))
        mock_send = mocker.patch("src.wechat_api.send_text_msg", return_value={"errcode": 0, "msgid": "m1"})

        message.handle_kf_event("kftoken", "wkxxxxxxx")

        sent_texts = [call.args[2] for call in mock_send.mock_calls]
        assert "查询阿里巴巴公司任务已完成" not in sent_texts
