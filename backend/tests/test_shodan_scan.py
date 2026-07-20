from unittest.mock import MagicMock, patch

import pytest
import shodan
from app.tools.shodan.scan import ShodanScanError, run


@patch("app.tools.shodan.scan.shodan.Shodan")
@patch.dict("os.environ", {"SHODAN_API_KEY": "fake-key"})
def test_run_with_ip_calls_shodan_directly(mock_shodan_cls):
    mock_api = MagicMock()
    mock_api.host.return_value = {"ip_str": "1.2.3.4", "data": []}
    mock_shodan_cls.return_value = mock_api

    result = run("1.2.3.4")

    mock_api.host.assert_called_once_with("1.2.3.4")
    assert result["ip_str"] == "1.2.3.4"


@patch("app.tools.shodan.scan.socket.gethostbyname", return_value="93.184.216.34")
@patch("app.tools.shodan.scan.shodan.Shodan")
@patch.dict("os.environ", {"SHODAN_API_KEY": "fake-key"})
def test_run_with_domain_resolves_first(mock_shodan_cls, mock_resolve):
    mock_api = MagicMock()
    mock_api.host.return_value = {"ip_str": "93.184.216.34", "data": []}
    mock_shodan_cls.return_value = mock_api

    run("example.com")

    mock_resolve.assert_called_once_with("example.com")
    mock_api.host.assert_called_once_with("93.184.216.34")


@patch.dict("os.environ", {}, clear=True)
def test_run_raises_without_api_key():
    with pytest.raises(ShodanScanError, match="SHODAN_API_KEY"):
        run("1.2.3.4")


@patch("app.tools.shodan.scan.socket.gethostbyname", side_effect=OSError)
@patch.dict("os.environ", {"SHODAN_API_KEY": "fake-key"})
def test_run_raises_on_unresolvable_domain(mock_resolve):
    with pytest.raises(ShodanScanError, match="Could not resolve"):
        run("not-a-real-domain.invalid")


@patch("app.tools.shodan.scan.shodan.Shodan")
@patch.dict("os.environ", {"SHODAN_API_KEY": "fake-key"})
def test_run_raises_on_shodan_api_error(mock_shodan_cls):
    mock_api = MagicMock()
    mock_api.host.side_effect = shodan.APIError("no information available")
    mock_shodan_cls.return_value = mock_api

    with pytest.raises(ShodanScanError, match="Shodan lookup failed"):
        run("1.2.3.4")
