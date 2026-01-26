{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = {nixpkgs, ...}: let
    inherit (nixpkgs) lib;
    forEachSystem = lib.genAttrs lib.systems.flakeExposed;
    localPkgs = system: nixpkgs.legacyPackages.${system};
  in {
    packages = forEachSystem (system: let
      pkgs = localPkgs system;
    in rec {
      py-networking =
        pkgs.callPackage ./package.nix {
        };

      default = py-networking;

      environment = pkgs.python313.withPackages (_: [py-networking]);
    });
  };
}

