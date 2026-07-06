{
  description = "OpenClaw Nextcloud skill — Node.js CLI wrapping Nextcloud APIs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Toolchain needed to develop and bundle the skill: node (with npm) to
        # install the JS deps and run the CLI, esbuild to bundle index.js ->
        # scripts/nextcloud.js. Exposed as a package so `nix shell` brings the
        # binaries onto PATH.
        toolchain = pkgs.buildEnv {
          name = "openclaw-nextcloud-toolchain";
          paths = with pkgs; [ nodejs_24 esbuild ];
        };
      in
      {
        packages.default = toolchain;

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [ nodejs_24 esbuild ];
        };
      });
}
