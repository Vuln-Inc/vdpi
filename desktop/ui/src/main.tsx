import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/components.css";
import { scrubUrlsInText } from "./lib/format";
import App from "./App";

function formatSafeErrorReason(reason: unknown): string {
  if (reason instanceof Error) {
    return scrubUrlsInText(reason.message || reason.name || "Unknown error");
  }
  if (typeof reason === "string") {
    return scrubUrlsInText(reason);
  }
  try {
    return scrubUrlsInText(String(reason));
  } catch {
    return "Unknown error";
  }
}

if (typeof window !== "undefined") {
  window.addEventListener("error", (event) => {
    const rawMessage =
      event.message ||
      (event.error instanceof Error ? event.error.message : "Unhandled error");
    const safeMessage = scrubUrlsInText(rawMessage);
    const safeSource = event.filename ? scrubUrlsInText(event.filename) : "";
    const location = safeSource
      ? ` (${safeSource}:${event.lineno}:${event.colno})`
      : "";
    console.error(`[vdpi] Unhandled error: ${safeMessage}${location}`);
    event.preventDefault();
  });

  window.addEventListener("unhandledrejection", (event) => {
    const safeReason = formatSafeErrorReason(event.reason);
    console.error(`[vdpi] Unhandled promise rejection: ${safeReason}`);
    event.preventDefault();
  });
}

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Missing #root mount element");
}

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
