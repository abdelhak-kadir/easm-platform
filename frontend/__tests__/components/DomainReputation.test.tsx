import { render, screen, fireEvent } from "@testing-library/react";
import DomainReputation from "../../components/DomainReputation";
import { Asset, AssetReputationResponse } from "../../types/scan";

const originalFetch = global.fetch;

function makeAsset(overrides: Partial<Asset> = {}): Asset {
  return {
    id: 1,
    value: "example.com",
    asset_type: "domain",
    status: "done",
    discovery_run_id: null,
    root_asset_id: 1,
    ...overrides,
  };
}

function makeResponse(overrides: Partial<AssetReputationResponse> = {}): AssetReputationResponse {
  return {
    root_asset: { id: 1, value: "example.com", asset_type: "domain" },
    total_ips: 3,
    listed_ips: 1,
    total_zone_listings: 2,
    ips: [],
    by_zone: [],
    unchecked_ips: [],
    generated_at: "2026-08-18T10:00:00+00:00",
    ...overrides,
  };
}

function mockFetch(data: unknown, ok = true) {
  (global.fetch as jest.Mock).mockResolvedValueOnce({
    ok,
    status: ok ? 200 : 500,
    json: async () => data,
  } as Response);
}

function renderPanel(overrides: { response?: AssetReputationResponse; onJumpToAsset?: jest.Mock } = {}) {
  const onJumpToAsset = overrides.onJumpToAsset ?? jest.fn();
  const utils = render(
    <DomainReputation
      apiBase="http://localhost:8000"
      asset={makeAsset()}
      refreshKey={0}
      onJumpToAsset={onJumpToAsset}
    />
  );
  return { ...utils, onJumpToAsset };
}

describe("DomainReputation", () => {
  beforeEach(() => {
    global.fetch = jest.fn() as jest.Mock;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("renders listed IPs with zone chips, Tor badge and AbuseIPDB score", async () => {
    mockFetch(
      makeResponse({
        ips: [
          {
            ip: "203.0.113.5",
            asset_id: 42,
            listed_count: 2,
            tor_exit: true,
            abuseipdb_score: 85,
            zones_checked: 8,
            zones_with_errors: 0,
            last_checked: "2026-08-17T09:00:00+00:00",
            zones: [
              { zone: "zen.spamhaus.org", code: "127.0.0.2", query: "5.113.0.203.zen.spamhaus.org", reason: "" },
              { zone: "bl.spamcop.net", code: "127.0.0.2", query: "", reason: "" },
            ],
          },
        ],
        by_zone: [{ zone: "zen.spamhaus.org", count: 1, listed_ips: ["203.0.113.5"] }],
      })
    );

    const { container } = renderPanel();
    // IP appears twice (row button + "Par zone" chip) → target the button
    await screen.findByRole("button", { name: "203.0.113.5" });

    expect(container.textContent).toContain("zen.spamhaus.org");
    expect(container.textContent).toContain("bl.spamcop.net");
    expect(container.textContent).toContain("2 listes");
    expect(container.textContent).toContain("Exit Tor");
    expect(container.textContent).toContain("AbuseIPDB 85");
    expect(container.textContent).toContain("Par zone RBL");
  });

  it("lists a clean IP as having no listing", async () => {
    mockFetch(
      makeResponse({
        listed_ips: 0,
        total_zone_listings: 0,
        ips: [
          {
            ip: "203.0.113.9",
            asset_id: 43,
            listed_count: 0,
            tor_exit: false,
            zones_checked: 8,
            zones_with_errors: 0,
            last_checked: "2026-08-17T09:00:00+00:00",
            zones: [],
          },
        ],
      })
    );

    const { container } = renderPanel();
    await screen.findByText("203.0.113.9");

    expect(container.textContent).toContain("aucune liste");
    expect(container.textContent).not.toContain("Exit Tor");
  });

  it("shows the unchecked-IPs warning section", async () => {
    mockFetch(makeResponse({ unchecked_ips: ["198.51.100.7", "198.51.100.8"] }));

    const { container } = renderPanel();
    await screen.findByText("IPs non vérifiées");

    expect(container.textContent).toContain("198.51.100.7");
    expect(container.textContent).toContain("198.51.100.8");
  });

  it("renders the empty state when no blacklist results exist", async () => {
    mockFetch(makeResponse({ total_ips: 1, listed_ips: 0, total_zone_listings: 0 }));

    const { container } = renderPanel();
    await screen.findByText("Aucun résultat IP Blacklist pour ce domaine.");

    expect(container.textContent).toContain("IPs vérifiées");
  });

  it("jumps to the IP asset when its row is clicked", async () => {
    mockFetch(
      makeResponse({
        ips: [
          {
            ip: "203.0.113.5",
            asset_id: 42,
            listed_count: 1,
            tor_exit: false,
            zones_checked: 8,
            zones_with_errors: 0,
            last_checked: "2026-08-17T09:00:00+00:00",
            zones: [{ zone: "zen.spamhaus.org" }],
          },
        ],
      })
    );

    const { onJumpToAsset } = renderPanel();
    const row = await screen.findByRole("button", { name: "203.0.113.5" });
    fireEvent.click(row);
    expect(onJumpToAsset).toHaveBeenCalledWith(42);
  });

  it("shows an error state with a retry button, and recovers on retry", async () => {
    (global.fetch as jest.Mock).mockRejectedValueOnce(new Error("network down"));
    mockFetch(
      makeResponse({
        ips: [
          {
            ip: "203.0.113.5",
            asset_id: 42,
            listed_count: 1,
            tor_exit: false,
            zones_checked: 8,
            zones_with_errors: 0,
            last_checked: "2026-08-17T09:00:00+00:00",
            zones: [],
          },
        ],
      })
    );

    renderPanel();
    await screen.findByText(/Erreur de chargement/);
    fireEvent.click(screen.getByRole("button", { name: "Réessayer" }));
    await screen.findByText("203.0.113.5");
  });
});
