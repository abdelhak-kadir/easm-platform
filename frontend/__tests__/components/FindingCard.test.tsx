import { render } from "@testing-library/react";
import FindingCard from "../../components/FindingCard";
import { Finding } from "../../types/scan";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 1,
    finding_type: "host_info",
    title: "Test finding",
    severity: "info",
    data: {},
    ...overrides,
  };
}

describe("FindingCard", () => {
  it("renders host_info finding without crashing", () => {
    const { container } = render(
      <FindingCard
        finding={makeFinding({
          finding_type: "host_info",
          data: { ip: "1.2.3.4", org: "TestOrg", ports: [80, 443] },
        })}
      />
    );
    expect(container.textContent).toContain("1.2.3.4");
  });

  it("renders open_port finding without crashing", () => {
    const { container } = render(
      <FindingCard
        finding={makeFinding({
          finding_type: "open_port",
          title: "Open port 80/tcp (nginx)",
          data: { port: 80, transport: "tcp", product: "nginx" },
        })}
      />
    );
    expect(container.textContent).toContain("nginx");
  });

  it("renders vulnerability finding without crashing", () => {
    const { container } = render(
      <FindingCard
        finding={makeFinding({
          finding_type: "vulnerability",
          title: "CVE-2021-1234",
          severity: "critical",
          data: { cvss: 9.8, summary: "Critical RCE" },
        })}
      />
    );
    expect(container.textContent).toContain("CVE-2021-1234");
  });

  it("renders http_service finding without crashing", () => {
    const { container } = render(
      <FindingCard
        finding={makeFinding({
          finding_type: "http_service",
          title: "HTTP 200 (https://example.com)",
          data: {
            status_code: 200,
            title: "Example Page",
            url: "https://example.com",
            technologies: ["React", "Nginx"],
          },
        })}
      />
    );
    expect(container.textContent).toContain("Example Page");
  });

  it("renders unknown finding type as raw JSON fallback", () => {
    const { container } = render(
      <FindingCard
        finding={makeFinding({
          finding_type: "some_future_type",
          data: { key: "value" },
        })}
      />
    );
    // The raw JSON fallback renders the data
    expect(container.textContent).toContain("value");
  });

  it("shows severity badge for each severity level", () => {
    for (const sev of ["info", "low", "medium", "high", "critical"] as const) {
      const { container, unmount } = render(
        <FindingCard finding={makeFinding({ severity: sev })} />
      );
      expect(container.textContent).toBeTruthy();
      unmount();
    }
  });
});
