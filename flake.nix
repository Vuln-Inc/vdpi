{
  description = "Zero-hassle, self-healing anti-DPI engine in Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs:
        let
          vdpi = pkgs.rustPlatform.buildRustPackage {
            pname = "vdpi";
            version = "0.6.3";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [ "-p" "vdpi" ];
            doCheck = false;

            meta = with pkgs.lib; {
              description = "Zero-hassle, self-healing anti-DPI engine in Rust";
              homepage = "https://github.com/Vuln-Inc/vdpi";
              license = licenses.mit;
              mainProgram = "vdpi";
              platforms = platforms.unix;
            };
          };
        in
        {
          inherit vdpi;
          default = vdpi;
        }
      );

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.system}.vdpi}/bin/vdpi";
        };
      });
    };
}
