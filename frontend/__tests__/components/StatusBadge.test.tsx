import { render, screen } from "@testing-library/react";
import StatusBadge, { statusVariant, statusLabel, statusColor } from "../../components/StatusBadge";

describe("StatusBadge", () => {
  it("renders each known status", () => {
    for (const status of ["pending", "running", "completed", "failed", "cancelled"]) {
      const { unmount } = render(<StatusBadge status={status} />);
      expect(screen.getByText(statusLabel(status))).toBeTruthy();
      unmount();
    }
  });

  it("maps max_rounds_reached to completed", () => {
    expect(statusVariant("max_rounds_reached")).toBe("completed");
  });

  it("defaults unknown status to pending", () => {
    expect(statusVariant("bogus")).toBe("pending");
  });

  it("renders pulsing dot when pulsing and running", () => {
    const { container } = render(<StatusBadge status="running" pulsing />);
    expect(container.querySelector(".status-dot--live")).toBeTruthy();
  });

  it("does not render pulsing dot when not pulsing", () => {
    const { container } = render(<StatusBadge status="running" />);
    expect(container.querySelector(".status-dot--live")).toBeFalsy();
  });

  it("returns a CSS color for every known status", () => {
    for (const status of ["pending", "running", "completed", "failed", "cancelled"]) {
      expect(statusColor(status)).toMatch(/^var\(--|^#|^rgba/);
    }
  });
});
