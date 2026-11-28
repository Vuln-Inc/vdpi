cask "vdpi-desktop" do
  version "0.6.3"
  sha256 "fe077fed12d67bad9ff277caed241b3e0f04519c04ab95dd14d474fc2cd06d68"

  url "https://github.com/Vuln-Inc/vdpi/releases/download/v#{version}/vdpi-desktop-macos-universal.dmg",
      verified: "github.com/Vuln-Inc/vdpi/"
  name "vdpi Desktop"
  desc "Native desktop GUI for the self-healing vdpi anti-DPI engine"
  homepage "https://vuln-inc.github.io/vdpi/"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on macos: ">= :monterey"

  app "vdpi Desktop.app"

  zap trash: [
    "~/Library/Application Support/com.vulninc.vdpi.desktop",
    "~/Library/Application Support/vdpi",
    "~/Library/Caches/com.vulninc.vdpi.desktop",
    "~/Library/Logs/vdpi",
    "~/Library/Preferences/com.vulninc.vdpi.desktop.plist",
  ]
end
