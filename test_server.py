import base64
import hashlib
import json
import os
import struct
import time

import pytest
from Crypto.Cipher import AES

os.environ.setdefault("WECHAT_TOKEN", "test-token")
os.environ.setdefault("WECHAT_ENCODING_AES_KEY", "a" * 43)
os.environ.setdefault("CorpTD", "test-corpid")
os.environ.setdefault("Secret", "test-secret")

import server  # noqa: E402  (env vars must be set before import)


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
    server._token_cache["access_token"] = None
    server._token_cache["expires_at"] = 0.0
    server._cursor_store.clear()
    yield


class TestSignatureCheck:
    def test_valid_signature_passes(self):
        sig = _sign("tok", "123", "abc", "hello")
        assert server._check_signature("tok", "123", "abc", "hello", sig) is True

    def test_invalid_signature_fails(self):
        assert server._check_signature("tok", "123", "abc", "hello", "deadbeef") is False


class TestAesRoundTrip:
    def test_encrypt_then_decrypt_returns_original(self):
        encrypt = _aes_encrypt(server.ENCODING_AES_KEY, "hello world")
        assert server._aes_decrypt(server.ENCODING_AES_KEY, encrypt) == "hello world"


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

        mock_get_token = mocker.patch("server.get_access_token", return_value="fake-access-token")
        mock_sync = mocker.patch(
            "server.sync_msg",
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
        mock_send = mocker.patch("server.send_text_msg", return_value={"errcode": 0, "errmsg": "ok", "msgid": "m1"})

        resp = self._post_event(client, event_xml)

        assert resp.status_code == 200
        assert resp.data.decode("utf-8") == "success"
        mock_sync.assert_called_once_with("kftoken123", "wkxxxxxxx")
        mock_send.assert_called_once_with("wmExternalUser1", "wkxxxxxxx", "成功接收消息")
        mock_get_token.assert_not_called()  # sync_msg/send_msg 内部会各自调用，此处已被 mock 掉

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
            "server.sync_msg",
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
        mock_send = mocker.patch("server.send_text_msg")

        resp = self._post_event(client, event_xml)

        assert resp.status_code == 200
        mock_send.assert_not_called()

    def test_non_kf_event_is_ignored(self, client, mocker):
        event_xml = "<xml><MsgType><![CDATA[event]]></MsgType><Event><![CDATA[enter_session]]></Event></xml>"
        mock_sync = mocker.patch("server.sync_msg")

        resp = self._post_event(client, event_xml)

        assert resp.status_code == 200
        mock_sync.assert_not_called()


class TestAccessToken:
    def test_fetches_and_caches_token(self, mocker):
        mock_get = mocker.patch("server.requests.get")
        mock_get.return_value.json.return_value = {"errcode": 0, "access_token": "tok1", "expires_in": 7200}

        token = server.get_access_token()
        token_again = server.get_access_token()

        assert token == "tok1"
        assert token_again == "tok1"
        mock_get.assert_called_once()  # 第二次应直接命中缓存

    def test_refetches_when_expired(self, mocker):
        mock_get = mocker.patch("server.requests.get")
        mock_get.return_value.json.return_value = {"errcode": 0, "access_token": "tok1", "expires_in": 7200}

        server.get_access_token()
        server._token_cache["expires_at"] = time.time() - 1  # 强制标记为已过期
        server.get_access_token()

        assert mock_get.call_count == 2

    def test_raises_on_error(self, mocker):
        mock_get = mocker.patch("server.requests.get")
        mock_get.return_value.json.return_value = {"errcode": 40001, "errmsg": "invalid credential"}

        with pytest.raises(RuntimeError):
            server.get_access_token()


class TestSyncMsg:
    def test_paginates_until_has_more_is_false(self, mocker):
        mocker.patch("server.get_access_token", return_value="tok")
        mock_post = mocker.patch("server.requests.post")
        mock_post.return_value.json.side_effect = [
            {"errcode": 0, "msg_list": [{"msgid": "1"}], "next_cursor": "c1", "has_more": 1},
            {"errcode": 0, "msg_list": [{"msgid": "2"}], "next_cursor": "c2", "has_more": 0},
        ]
        mocker.patch("server._save_cursors")  # mock 掉文件保存

        msgs = server.sync_msg("kftoken", "wkxxxxxxx")

        assert [m["msgid"] for m in msgs] == ["1", "2"]
        assert server._cursor_store["wkxxxxxxx"] == "c2"
        assert mock_post.call_count == 2

    def test_raises_on_error(self, mocker):
        mocker.patch("server.get_access_token", return_value="tok")
        mock_post = mocker.patch("server.requests.post")
        mock_post.return_value.json.return_value = {"errcode": 60011, "errmsg": "not a valid openkfid"}

        with pytest.raises(RuntimeError):
            server.sync_msg("kftoken", "wkxxxxxxx")

    def test_saves_cursor_after_each_page(self, mocker):
        mocker.patch("server.get_access_token", return_value="tok")
        mock_post = mocker.patch("server.requests.post")
        mock_post.return_value.json.side_effect = [
            {"errcode": 0, "msg_list": [], "next_cursor": "c1", "has_more": 1},
            {"errcode": 0, "msg_list": [], "next_cursor": "c2", "has_more": 0},
        ]
        mock_save = mocker.patch("server._save_cursors")

        server.sync_msg("kftoken", "wkxxxxxxx")

        assert mock_save.call_count == 2  # 每次更新游标后都调用


class TestCursorPersistence:
    def test_load_cursors_from_file(self, mocker, tmp_path):
        cursor_file = tmp_path / "cursors.json"
        cursor_file.write_text('{"wkAAAAA": "cursor123"}')
        mocker.patch("server.CURSOR_FILE", str(cursor_file))

        server._load_cursors()

        assert server._cursor_store == {"wkAAAAA": "cursor123"}

    def test_load_cursors_handles_missing_file(self, mocker, tmp_path):
        mocker.patch("server.CURSOR_FILE", str(tmp_path / "nonexistent.json"))

        server._load_cursors()  # 不应抛异常

        assert server._cursor_store == {}

    def test_save_cursors_writes_to_file(self, mocker, tmp_path):
        cursor_file = tmp_path / "cursors.json"
        mocker.patch("server.CURSOR_FILE", str(cursor_file))
        server._cursor_store = {"wkBBBBB": "cursor456"}

        server._save_cursors()

        assert cursor_file.exists()
        assert json.loads(cursor_file.read_text()) == {"wkBBBBB": "cursor456"}


class TestSendTextMsg:
    def test_sends_expected_payload(self, mocker):
        mocker.patch("server.get_access_token", return_value="tok")
        mock_post = mocker.patch("server.requests.post")
        mock_post.return_value.json.return_value = {"errcode": 0, "errmsg": "ok", "msgid": "m1"}

        result = server.send_text_msg("wmUser1", "wkxxxxxxx", "成功接收消息")

        assert result["msgid"] == "m1"
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["touser"] == "wmUser1"
        assert kwargs["json"]["open_kfid"] == "wkxxxxxxx"
        assert kwargs["json"]["text"]["content"] == "成功接收消息"

    def test_raises_on_error(self, mocker):
        mocker.patch("server.get_access_token", return_value="tok")
        mock_post = mocker.patch("server.requests.post")
        mock_post.return_value.json.return_value = {"errcode": 95003, "errmsg": "not allow to send message"}

        with pytest.raises(RuntimeError):
            server.send_text_msg("wmUser1", "wkxxxxxxx", "成功接收消息")


class TestDownloadMedia:
    def test_download_success(self, mocker, tmp_path):
        mocker.patch("server.get_access_token", return_value="tok")
        mock_get = mocker.patch("server.requests.get")
        mock_resp = mock_get.return_value
        mock_resp.headers = {
            "Content-Type": "image/png",
            "Content-Disposition": 'attachment; filename="test.png"',
        }
        mock_resp.iter_content.return_value = [b"fake", b"image", b"data"]

        result = server.download_media("media123", save_dir=str(tmp_path))

        assert result["success"] is True
        assert result["filename"].startswith("test_")
        assert result["filename"].endswith(".png")
        assert result["size"] == 13
        assert os.path.exists(result["filepath"])

    def test_download_api_error(self, mocker):
        mocker.patch("server.get_access_token", return_value="tok")
        mock_get = mocker.patch("server.requests.get")
        mock_resp = mock_get.return_value
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.json.return_value = {"errcode": 40007, "errmsg": "invalid media_id"}

        result = server.download_media("bad_media")

        assert result["success"] is False
        assert "invalid media_id" in result["error"]

    def test_download_without_filename(self, mocker, tmp_path):
        mocker.patch("server.get_access_token", return_value="tok")
        mock_get = mocker.patch("server.requests.get")
        mock_resp = mock_get.return_value
        mock_resp.headers = {"Content-Type": "application/octet-stream"}
        mock_resp.iter_content.return_value = [b"data"]

        result = server.download_media("media_long_id_12345", save_dir=str(tmp_path))

        assert result["success"] is True
        assert result["filename"].startswith("media_long_id_12")


class TestFileMessageHandling:
    def test_file_message_triggers_download_and_reply(self, mocker, tmp_path):
        mocker.patch("server.get_access_token", return_value="tok")
        mock_sync = mocker.patch(
            "server.sync_msg",
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
            "server.download_media",
            return_value={"success": True, "filepath": str(tmp_path / "test.pdf"), "filename": "test.pdf", "size": 2048000},
        )
        mock_send = mocker.patch("server.send_text_msg", return_value={"errcode": 0, "msgid": "m1"})

        server._handle_kf_event("kftoken", "wkxxxxxxx")

        mock_download.assert_called_once_with("media123")
        mock_send.assert_called_once()
        _, args, _ = mock_send.mock_calls[0]
        assert "已成功接收test.pdf文件" in args[2]
        assert "1.95MB" in args[2]

    def test_image_message_triggers_download(self, mocker):
        mocker.patch(
            "server.sync_msg",
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
            "server.download_media",
            return_value={"success": True, "filepath": "/tmp/pic.jpg", "filename": "pic.jpg", "size": 512000},
        )
        mocker.patch("server.send_text_msg")

        server._handle_kf_event("kftoken", "wkxxxxxxx")

        mock_download.assert_called_once_with("img123")

    def test_download_failure_replies_error(self, mocker):
        mocker.patch(
            "server.sync_msg",
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
        mocker.patch("server.download_media", return_value={"success": False, "error": "invalid media_id"})
        mock_send = mocker.patch("server.send_text_msg")

        server._handle_kf_event("kftoken", "wkxxxxxxx")

        _, args, _ = mock_send.mock_calls[0]
        assert "文件接收失败" in args[2]
        assert "invalid media_id" in args[2]

    def test_voice_message_triggers_download_and_fixed_reply(self, mocker, tmp_path):
        mocker.patch(
            "server.sync_msg",
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
            "server.download_media",
            return_value={"success": True, "filepath": str(tmp_path / "test.amr"), "filename": "test.amr", "size": 20480},
        )
        mock_send = mocker.patch("server.send_text_msg")

        server._handle_kf_event("kftoken", "wkxxxxxxx")

        mock_download.assert_called_once_with("voice123")
        _, args, _ = mock_send.mock_calls[0]
        assert args[2] == "已接收语音消息"

    def test_voice_download_failure_replies_error(self, mocker):
        mocker.patch(
            "server.sync_msg",
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
        mocker.patch("server.download_media", return_value={"success": False, "error": "invalid media_id"})
        mock_send = mocker.patch("server.send_text_msg")

        server._handle_kf_event("kftoken", "wkxxxxxxx")

        _, args, _ = mock_send.mock_calls[0]
        assert "文件接收失败" in args[2]

    def test_text_message_does_not_download(self, mocker):
        mocker.patch(
            "server.sync_msg",
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
        mock_download = mocker.patch("server.download_media")
        mocker.patch("server.send_text_msg")

        server._handle_kf_event("kftoken", "wkxxxxxxx")

        mock_download.assert_not_called()
