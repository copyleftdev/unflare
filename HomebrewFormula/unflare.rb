class Unflare < Formula
  desc "High-performance Cloudflare intelligence toolkit"
  homepage "https://github.com/copyleftdev/unflare"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/copyleftdev/unflare/releases/download/v0.1.0/unflare-macos-aarch64"
      sha256 "a4e0acc1f83f554c4877e7922c69" # Update with actual sha256
    else
      url "https://github.com/copyleftdev/unflare/releases/download/v0.1.0/unflare-macos-x86_64"
      sha256 "560de6ed49ffcb079cb3ec4af59a" # Update with actual sha256
    end
  end

  on_linux do
    url "https://github.com/copyleftdev/unflare/releases/download/v0.1.0/unflare-linux-x86_64"
    sha256 "4194571722c994f7047087c2aa5d" # Update with actual sha256
  end

  def install
    if OS.mac? && Hardware::CPU.arm?
      bin.install "unflare-macos-aarch64" => "unflare"
    elsif OS.mac?
      bin.install "unflare-macos-x86_64" => "unflare"
    else
      bin.install "unflare-linux-x86_64" => "unflare"
    end
  end

  test do
    assert_match "unflare", shell_output("#{bin}/unflare version")
  end
end
