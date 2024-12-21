{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
    in
    {
      packages = nixpkgs.lib.genAttrs systems (system: {
        gh-audit = nixpkgs.legacyPackages.${system}.callPackage ./package.nix { };
        default = self.packages.${system}.gh-audit;
      });
    };
}
