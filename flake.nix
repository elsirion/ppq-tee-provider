{
  description = "PPQ TEE in-process LLM provider and local OpenAI-compatible proxy";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        lib = pkgs.lib;
        toolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };
        # The release build uses the minimal profile: a toolchain carrying
        # rust-src/rust-docs leaks its own store path into the binary and
        # drags ~2 GB of toolchain into the runtime closure of the package.
        buildToolchain = pkgs.rust-bin.stable.latest.minimal;
        rustPlatform = pkgs.makeRustPlatform {
          cargo = buildToolchain;
          rustc = buildToolchain;
        };
        manifest = lib.importTOML ./crates/ppq-tee-proxy/Cargo.toml;
      in {
        packages.default = rustPlatform.buildRustPackage {
          pname = manifest.package.name;
          version = manifest.package.version;
          # Only what the build reads: keeps docs, fixtures' provenance notes
          # and editor state out of the input hash.
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./crates ];
          };
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "-p" "ppq-tee-proxy" ];
          # The proxy's own tests plus the library's offline suite; the live
          # tests are `#[ignore]` and never run here.
          cargoTestFlags = [ "-p" "ppq-tee-proxy" "-p" "ppq-tee" ];
          meta = {
            description = manifest.package.description;
            license = lib.licenses.mit;
            mainProgram = "ppq-tee-proxy";
          };
        };

        apps.default = {
          type = "app";
          program = lib.getExe self.packages.${system}.default;
        };

        devShells.default = pkgs.mkShell {
          packages = [ toolchain pkgs.cargo-nextest pkgs.pkg-config ];
          # rustls only: no openssl in the shell, so an accidental
          # native-tls dependency fails the build instead of silently working.
          shellHook = ''
            echo "ppq-tee dev shell — $(rustc --version)"
          '';
        };
      }) // {
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.ppq-tee-proxy;
        in {
          options.services.ppq-tee-proxy = {
            enable = lib.mkEnableOption "the local OpenAI-compatible proxy for PPQ.AI's attested TEE models";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              defaultText = lib.literalExpression "ppq-tee-proxy.packages.\${system}.default";
              description = "The ppq-tee-proxy package to run.";
            };

            listenAddress = lib.mkOption {
              type = lib.types.str;
              default = "127.0.0.1";
              description = ''
                Address to listen on. The proxy has no client authentication
                of its own; anything that can reach it can spend the API key.
              '';
            };

            port = lib.mkOption {
              type = lib.types.port;
              default = 8090;
              description = "TCP port to serve the OpenAI-compatible API on.";
            };

            apiKeyFile = lib.mkOption {
              type = lib.types.path;
              example = "/run/secrets/ppq-api-key";
              description = ''
                File containing the PPQ API key. Read through systemd's
                credential mechanism, so it may be root-only and must not be
                in the Nix store.
              '';
            };

            baseUrl = lib.mkOption {
              type = lib.types.str;
              default = "https://api.ppq.ai";
              description = "PPQ API base URL.";
            };

            reattestAfter = lib.mkOption {
              type = lib.types.str;
              default = "1h";
              example = "30m";
              description = ''
                Re-attest the enclave once the current attestation is this
                old, even if nothing has failed. A rejected key triggers an
                earlier re-attestation regardless.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.ppq-tee-proxy = {
              description = "OpenAI-compatible proxy to PPQ.AI attested TEE models";
              wantedBy = [ "multi-user.target" ];
              wants = [ "network-online.target" ];
              after = [ "network-online.target" ];

              serviceConfig = {
                ExecStart = lib.escapeShellArgs [
                  (lib.getExe cfg.package)
                  "--listen" "${cfg.listenAddress}:${toString cfg.port}"
                  "--api-key-file" "%d/api-key"
                  "--base-url" cfg.baseUrl
                  "--reattest-after" cfg.reattestAfter
                ];
                LoadCredential = [ "api-key:${cfg.apiKeyFile}" ];
                DynamicUser = true;
                # Attestation needs the network up; a transient failure at
                # boot should retry, not leave the service dead.
                Restart = "on-failure";
                RestartSec = "5s";

                # Hardening. The service needs nothing but outbound TCP and
                # its credential.
                CapabilityBoundingSet = "";
                AmbientCapabilities = "";
                NoNewPrivileges = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                PrivateDevices = true;
                PrivateTmp = true;
                PrivateUsers = true;
                ProtectClock = true;
                ProtectControlGroups = true;
                ProtectHome = true;
                ProtectHostname = true;
                ProtectKernelLogs = true;
                ProtectKernelModules = true;
                ProtectKernelTunables = true;
                ProtectProc = "invisible";
                ProtectSystem = "strict";
                RemoveIPC = true;
                RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
                RestrictNamespaces = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                SystemCallArchitectures = "native";
                SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
                UMask = "0077";
              };
            };
          };
        };
    };
}
