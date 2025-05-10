{
  description = "Nix for development of rustls-gcp-kms";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, fenix, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-darwin"
      ];

      perSystem =
        { system, pkgs, ... }:
        let
          rust = pkgs.fenix.toolchainOf {
            channel = "1.82";
            sha256 = "sha256-yMuSb5eQPO/bHv+Bcf/US8LVMbf/G/0MSfiPwBhiPpk=";
          };

          rustToolchain = pkgs.fenix.combine [
            (rust.withComponents [
              "cargo"
              "clippy"
              "rustc"
              "rust-src"
              "rustfmt"
              "rust-analyzer"
            ])
          ];
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ fenix.overlays.default ];
          };

          formatter = pkgs.nixpkgs-fmt;

          devShells = {
            default = pkgs.mkShell {
              packages = with pkgs; [
                nixd
                rustToolchain
                vscode-extensions.vadimcn.vscode-lldb
              ];

              shellHook = ''
                export RUST_SRC_PATH="${rust.rust-src}/lib/rustlib/src/rust/library";
                export PATH=$HOME/.cargo/bin:$PATH
              '';
            };
          };
        };
    };
}
