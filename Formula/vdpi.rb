class Vdpi < Formula
  desc "Zero-hassle, self-healing anti-DPI engine in Rust"
  homepage "https://vuln-inc.github.io/vdpi/"
  version "0.6.3"
  license "MIT"

  on_macos do
    url "https://github.com/Vuln-Inc/vdpi/releases/download/v#{version}/vdpi-macos-universal.tar.gz"
    sha256 "932808b4965b3d89365a8666a9e2b6b763858a5bb09a9df2ebfc13853a61f612"
  end

  on_linux do
    on_intel do
      url "https://github.com/Vuln-Inc/vdpi/releases/download/v#{version}/vdpi-linux-x86_64.tar.gz"
      sha256 "67f6808a9020f597d7f4ecfb7a28359e0647842836ef8d76e92d46e16879c0e0"
    end
    on_arm do
      url "https://github.com/Vuln-Inc/vdpi/releases/download/v#{version}/vdpi-linux-arm64.tar.gz"
      sha256 "50e889613a5a96b3ec30eb0c6a2224d380332b6c2a010427fa4841450205c838"
    end
  end

  def install
    bin.install "vdpi"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/vdpi --version")
  end
end
