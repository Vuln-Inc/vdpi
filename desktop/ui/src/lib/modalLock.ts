let activeLocks = 0;
let savedBodyOverflow: string | null = null;
let appliedRootInert = false;

export function acquireModalLock(): () => void {
  if (typeof document === "undefined") {
    return () => {};
  }

  if (activeLocks === 0) {
    if (document.body) {
      savedBodyOverflow = document.body.style.overflow;
      document.body.style.overflow = "hidden";
    } else {
      savedBodyOverflow = null;
    }

    const root = document.getElementById("root") as
      | (HTMLElement & { inert?: boolean })
      | null;
    if (root && !root.hasAttribute("inert") && !root.inert) {
      root.inert = true;
      root.setAttribute("inert", "");
      appliedRootInert = true;
    } else {
      appliedRootInert = false;
    }
  }

  activeLocks += 1;

  let released = false;
  return () => {
    if (released) {
      return;
    }
    released = true;

    if (activeLocks > 0) {
      activeLocks -= 1;
    }

    if (activeLocks === 0) {
      if (typeof document !== "undefined") {
        if (document.body) {
          document.body.style.overflow = savedBodyOverflow ?? "";
        }
        if (appliedRootInert) {
          const root = document.getElementById("root") as
            | (HTMLElement & { inert?: boolean })
            | null;
          if (root) {
            root.inert = false;
            root.removeAttribute("inert");
          }
        }
      }
      savedBodyOverflow = null;
      appliedRootInert = false;
    }
  };
}
