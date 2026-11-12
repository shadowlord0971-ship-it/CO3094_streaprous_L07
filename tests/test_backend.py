import unittest
from unittest.mock import MagicMock, patch

import apps.sampleapp as sampleapp
from daemon.backend import create_backend, run_backend


class BackendTransportTests(unittest.TestCase):
    def test_create_backend_forwards_transport(self):
        with patch("daemon.backend.run_backend") as start:
            create_backend(
                "127.0.0.1", 9000, {"route": "x"}, "lo0", "standard"
            )
        start.assert_called_once_with(
            "127.0.0.1", 9000, {"route": "x"}, "lo0", "standard"
        )

    def test_auto_localhost_uses_standard(self):
        with patch("daemon.backend.run_backend_standard") as start:
            run_backend("127.0.0.1", 9000, {})
        start.assert_called_once_with("127.0.0.1", 9000, {})

    def test_standard_transport_uses_standard_for_any_ip(self):
        with patch("daemon.backend.run_backend_standard") as start:
            run_backend("0.0.0.0", 9000, {}, transport="standard")
        start.assert_called_once_with("0.0.0.0", 9000, {})

    def test_async_transport_uses_async_server(self):
        def consume(coroutine):
            close = getattr(coroutine, "close", None)
            if close is not None:
                close()

        with patch(
            "daemon.backend.async_server", new_callable=MagicMock
        ) as server, patch(
            "daemon.backend._run_coroutine", side_effect=consume
        ) as runner:
            run_backend("127.0.0.1", 9000, {}, transport="async")
        server.assert_called_once_with("127.0.0.1", 9000, {})
        runner.assert_called_once()

    def test_raw_transport_reaches_raw_socket(self):
        with patch(
            "daemon.backend.create_raw_socket",
            side_effect=PermissionError("no root"),
        ) as raw:
            run_backend(
                "0.0.0.0",
                9000,
                {},
                interface="eth0",
                transport="raw",
            )
        raw.assert_called_once_with()

    def test_auto_nonlocal_uses_raw_socket(self):
        with patch(
            "daemon.backend.create_raw_socket",
            side_effect=PermissionError("no root"),
        ) as raw:
            run_backend("0.0.0.0", 9000, {}, interface="eth0")
        raw.assert_called_once_with()

    def test_unknown_transport_is_rejected(self):
        with self.assertRaises(ValueError):
            run_backend("127.0.0.1", 9000, {}, transport="teleport")


class BackendCliTests(unittest.TestCase):
    def test_main_standard_skips_rst(self):
        import start_backend

        with patch("start_backend.create_backend") as create, patch(
            "start_backend.setup_rst_block"
        ) as rst:
            start_backend.main(
                "0.0.0.0", 9000, interface="eth0", transport="standard"
            )
        create.assert_called_once_with(
            "0.0.0.0",
            9000,
            {},
            "eth0",
            transport="standard",
        )
        rst.assert_not_called()

    def test_main_raw_sets_rst(self):
        import start_backend

        with patch("start_backend.create_backend") as create, patch(
            "start_backend.setup_rst_block"
        ) as rst:
            start_backend.main(
                "0.0.0.0", 9000, interface="eth0", transport="raw"
            )
        create.assert_called_once_with(
            "0.0.0.0",
            9000,
            {},
            "eth0",
            transport="raw",
        )
        rst.assert_called_once_with("0.0.0.0", 9000)

    def test_main_auto_localhost_skips_rst(self):
        import start_backend

        with patch("start_backend.create_backend") as create, patch(
            "start_backend.setup_rst_block"
        ) as rst:
            start_backend.main(
                "127.0.0.1", 9000, interface="lo0", transport="auto"
            )
        create.assert_called_once_with(
            "127.0.0.1",
            9000,
            {},
            "lo0",
            transport="auto",
        )
        rst.assert_not_called()


class SampleAppTransportTests(unittest.TestCase):
    def test_create_sampleapp_forwards_transport(self):
        with patch("apps.sampleapp.install_auth") as install, patch.object(
            sampleapp.app, "prepare_address"
        ) as prepare, patch.object(sampleapp.app, "run") as run:
            sampleapp.create_sampleapp("127.0.0.1", 9000, "standard")
        install.assert_called_once_with(sampleapp.app)
        prepare.assert_called_once_with("127.0.0.1", 9000)
        run.assert_called_once_with(transport="standard")


if __name__ == "__main__":
    unittest.main()
