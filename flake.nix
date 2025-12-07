{
  description = "High-performance Cloudflare intelligence toolkit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    zig-overlay.url = "github:mitchellh/zig-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, zig-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ zig-overlay.overlays.default ];
        };
        zig = pkgs.zigpkgs."0.14.0";
      in
      {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "unflare";
          version = "0.1.0";

          src = ./.;

          nativeBuildInputs = [ zig ];
          buildInputs = [ pkgs.openssl ];

          dontConfigure = true;
          dontInstall = true;

          buildPhase = ''
            mkdir -p $out/bin
            zig build -Doptimize=ReleaseSafe --prefix $out
          '';

          meta = with pkgs.lib; {
            description = "High-performance Cloudflare intelligence toolkit";
            homepage = "https://github.com/copyleftdev/unflare";
            license = licenses.mit;
            maintainers = [ ];
            platforms = platforms.unix;
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [ zig pkgs.openssl ];
        };
      }
    );
}
