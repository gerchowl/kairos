{
  description = "Kairos dev shell — uv, ruff, prek, node (CSS build) + guardrails gates";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.guardrails.url = "github:gerchowl/guardrails";
  outputs = { self, nixpkgs, guardrails }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});
    in {
      devShells = forAll (system: pkgs: {
        # Python repo: pull just guardrails' `gates` (shell scripts on PATH as
        # guardrails-<name>), not the full Rust toolbelt (mkDevShell). The
        # adr-matrix gate is wired in .pre-commit-config.yaml.
        default = pkgs.mkShell {
          packages = [ guardrails.lib.${system}.gates ]
            ++ (with pkgs; [ uv ruff prek gitleaks nodejs_24 python312 ]);
          shellHook = ''
            prek install --overwrite >/dev/null 2>&1 || true
          '';
        };
      });
    };
}
