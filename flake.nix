{
  description = "Kairos dev shell — uv, ruff, prek, node (CSS build)";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }:
    let
      forAll = f: nixpkgs.lib.genAttrs [ "aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux" ]
        (system: f nixpkgs.legacyPackages.${system});
    in {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [ uv ruff prek nodejs_24 python312 ];
          shellHook = ''
            prek install --overwrite >/dev/null 2>&1 || true
          '';
        };
      });
    };
}
