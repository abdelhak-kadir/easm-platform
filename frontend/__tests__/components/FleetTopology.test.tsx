import { render, screen, fireEvent } from "@testing-library/react";
import FleetTopology from "../../components/FleetTopology";
import { Asset } from "../../types/scan";

function makeAsset(overrides: Partial<Asset> = {}): Asset {
  return {
    id: 1,
    value: "example.com",
    asset_type: "domain",
    status: "done",
    discovery_run_id: null,
    root_asset_id: null,
    ...overrides,
  };
}

const assets: Asset[] = [
  makeAsset({ id: 1, value: "example.com", asset_type: "domain" }),
  makeAsset({ id: 2, value: "www.example.com", asset_type: "subdomain", root_asset_id: 1 }),
  makeAsset({ id: 3, value: "mail.example.com", asset_type: "subdomain", root_asset_id: 1 }),
  makeAsset({ id: 4, value: "93.184.216.34", asset_type: "ip", root_asset_id: 1 }),
  makeAsset({ id: 5, value: "acme.com", asset_type: "domain" }),
  makeAsset({ id: 6, value: "api.acme.com", asset_type: "subdomain", root_asset_id: 5 }),
  makeAsset({ id: 7, value: "203.0.113.9", asset_type: "ip" }),
];

const jobs = [
  { id: 10, asset_id: 2, status: "running" },
  { id: 11, asset_id: 3, status: "completed" },
  { id: 12, asset_id: 4, status: "failed" },
  { id: 13, asset_id: 6, status: "pending" },
  // Latest (highest id) wins per asset.
  { id: 14, asset_id: 2, status: "completed" },
];

function renderTopo(onSelectAsset = jest.fn()) {
  return {
    ...render(<FleetTopology assets={assets} jobs={jobs} onSelectAsset={onSelectAsset} />),
    onSelectAsset,
  };
}

describe("FleetTopology", () => {
  it("groups subdomains and IPs under their root domain", () => {
    const { container } = renderTopo();

    // Root rows
    expect(container.textContent).toContain("example.com");
    expect(container.textContent).toContain("acme.com");

    // Members present, subdomains before IPs within the group
    const text = container.textContent ?? "";
    expect(text.indexOf("www.example.com")).toBeGreaterThan(text.indexOf("example.com"));
    expect(text.indexOf("mail.example.com")).toBeLessThan(text.indexOf("93.184.216.34"));

    // Root chip on both domains
    expect(screen.getAllByText("Root").length).toBe(2);

    // Group counters
    expect(container.textContent).toContain("3 actifs");
    expect(container.textContent).toContain("1 actif");
  });

  it("uses the latest job status per asset", () => {
    const { container } = renderTopo();

    // Asset 2 has jobs running (id 10) then completed (id 14) → completed
    expect(container.textContent).toContain("Terminé");
    expect(container.textContent).toContain("Échec"); // asset 4
    expect(container.textContent).toContain("En attente"); // asset 6
  });

  it("puts assets without a root domain in the Non groupés bucket", () => {
    const { container } = renderTopo();

    expect(container.textContent).toContain("Non groupés");
    expect(container.textContent).toContain("203.0.113.9");
    expect(container.textContent).toContain("Aucun scan");
  });

  it("calls onSelectAsset when a root or a member is clicked", () => {
    const { onSelectAsset } = renderTopo();

    fireEvent.click(screen.getByText("api.acme.com"));
    expect(onSelectAsset).toHaveBeenCalledWith(6);

    fireEvent.click(screen.getByText("acme.com"));
    expect(onSelectAsset).toHaveBeenCalledWith(5);
  });

  it("filters groups and members by search", () => {
    const { container, onSelectAsset } = renderTopo();

    fireEvent.change(screen.getByPlaceholderText("Filtrer…"), {
      target: { value: "mail" },
    });

    expect(container.textContent).toContain("mail.example.com");
    expect(container.textContent).not.toContain("acme.com");
    expect(container.textContent).not.toContain("www.example.com");
    // Filtering hides nothing the user clicked before.
    expect(onSelectAsset).not.toHaveBeenCalled();
  });

  it("renders nothing when there are no assets", () => {
    const { container } = render(
      <FleetTopology assets={[]} jobs={[]} onSelectAsset={jest.fn()} />
    );
    expect(container.innerHTML).toBe("");
  });
});
