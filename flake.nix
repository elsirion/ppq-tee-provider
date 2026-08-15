{
  description = "PPQ TEE in-process LLM provider";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        toolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };
      in {
        devShells.default = pkgs.mkShell {
          packages = [ toolchain pkgs.cargo-nextest pkgs.pkg-config ];
          # rustls only: no openssl in the shell, so an accidental
          # native-tls dependency fails the build instead of silently working.
          shellHook = ''
            echo "ppq-tee dev shell — $(rustc --version)"
          '';
        };
      });
}
